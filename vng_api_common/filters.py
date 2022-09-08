import logging
from urllib.parse import urlencode, urlparse

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import models
from django.forms.widgets import URLInput
from django.http import QueryDict
from django.utils.translation import gettext_lazy as _

from django_filters import fields, filters
from django_filters.constants import EMPTY_VALUES
from django_filters.rest_framework import DjangoFilterBackend
from djangorestframework_camel_case.parser import CamelCaseJSONParser
from djangorestframework_camel_case.render import CamelCaseJSONRenderer
from djangorestframework_camel_case.util import underscoreize
from rest_framework.request import Request
from rest_framework.views import APIView

from .constants import FILTER_URL_DID_NOT_RESOLVE
from .search import is_search_view
from .utils import NotAViewSet, get_resource_for_path
from .validators import validate_rsin

logger = logging.getLogger(__name__)
from drf_spectacular.contrib.django_filters import DjangoFilterExtension

from django.db import models

from drf_spectacular.drainage import add_trace_message, get_override, has_override, warn
from drf_spectacular.extensions import OpenApiFilterExtension
from drf_spectacular.plumbing import (
    build_array_type, build_basic_type, build_parameter_type, follow_field_source, get_type_hints,
    get_view_model, is_basic_type,
)
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter

_NoHint = object()

class Backend(DjangoFilterBackend):
    target_class = 'django_filters.rest_framework.DjangoFilterBackend'

    def get_schema_operation_parameters(self, auto_schema, *args, **kwargs):

        model = get_view_model(auto_schema.view)
        if not model:
            return []

        filterset_class = self.get_filterset_class(auto_schema.view,  auto_schema.view.get_queryset())

        if not filterset_class:
            return []

        result = []
        with add_trace_message(filterset_class.__name__):
            for field_name, filter_field in filterset_class.base_filters.items():
                result += self.resolve_filter_field(
                    auto_schema, model, filterset_class, field_name, filter_field
                )
        return result

    def resolve_filter_field(self, auto_schema, model, filterset_class, field_name, filter_field):
        from django_filters import filters

        unambiguous_mapping = {
            filters.CharFilter: OpenApiTypes.STR,
            filters.BooleanFilter: OpenApiTypes.BOOL,
            filters.DateFilter: OpenApiTypes.DATE,
            filters.DateTimeFilter: OpenApiTypes.DATETIME,
            filters.IsoDateTimeFilter: OpenApiTypes.DATETIME,
            filters.TimeFilter: OpenApiTypes.TIME,
            filters.UUIDFilter: OpenApiTypes.UUID,
            filters.DurationFilter: OpenApiTypes.DURATION,
            filters.OrderingFilter: OpenApiTypes.STR,
            filters.TimeRangeFilter: OpenApiTypes.TIME,
            filters.DateFromToRangeFilter: OpenApiTypes.DATE,
            filters.IsoDateTimeFromToRangeFilter: OpenApiTypes.DATETIME,
            filters.DateTimeFromToRangeFilter: OpenApiTypes.DATETIME,
        }
        filter_method = self._get_filter_method(filterset_class, filter_field)
        filter_method_hint = self._get_filter_method_hint(filter_method)
        filter_choices = self._get_explicit_filter_choices(filter_field)
        schema_from_override = False

        if has_override(filter_field, 'field') or has_override(filter_method, 'field'):
            schema_from_override = True
            annotation = (
                get_override(filter_field, 'field') or get_override(filter_method, 'field')
            )
            if is_basic_type(annotation):
                schema = build_basic_type(annotation)
            else:
                # allow injecting raw schema via @extend_schema_field decorator
                schema = annotation
        elif filter_method_hint is not _NoHint:
            if is_basic_type(filter_method_hint):
                schema = build_basic_type(filter_method_hint)
            else:
                schema = build_basic_type(OpenApiTypes.STR)
        elif isinstance(filter_field, tuple(unambiguous_mapping)):
            for cls in filter_field.__class__.__mro__:
                if cls in unambiguous_mapping:
                    schema = build_basic_type(unambiguous_mapping[cls])
                    break
        elif isinstance(filter_field, (filters.NumberFilter, filters.NumericRangeFilter)):
            # NumberField is underspecified by itself. try to find the
            # type that makes the most sense or default to generic NUMBER
            model_field = self._get_model_field(filter_field, model)
            if isinstance(model_field, (models.IntegerField, models.AutoField)):
                schema = build_basic_type(OpenApiTypes.INT)
            elif isinstance(model_field, models.FloatField):
                schema = build_basic_type(OpenApiTypes.FLOAT)
            elif isinstance(model_field, models.DecimalField):
                schema = build_basic_type(OpenApiTypes.NUMBER)  # TODO may be improved
            else:
                schema = build_basic_type(OpenApiTypes.NUMBER)
        elif isinstance(filter_field, (filters.ChoiceFilter, filters.MultipleChoiceFilter)):
            try:
                schema = self._get_schema_from_model_field(auto_schema, filter_field, model)
            except Exception:
                if filter_choices and is_basic_type(type(filter_choices[0])):
                    # fallback to type guessing from first choice element
                    schema = build_basic_type(type(filter_choices[0]))
                else:
                    warn(
                        f'Unable to guess choice types from values, filter method\'s type hint '
                        f'or find "{field_name}" in model. Defaulting to string.'
                    )
                    schema = build_basic_type(OpenApiTypes.STR)
        else:
            # the last resort is to look up the type via the model or queryset field
            # and emit a warning if we were unsuccessful.
            try:
                schema = self._get_schema_from_model_field(auto_schema, filter_field, model)
            except Exception as exc:  # pragma: no cover
                warn(
                    f'Exception raised while trying resolve model field for django-filter '
                    f'field "{field_name}". Defaulting to string (Exception: {exc})'
                )
                schema = build_basic_type(OpenApiTypes.STR)

        # primary keys are usually non-editable (readOnly=True) and map_model_field correctly
        # signals that attribute. however this does not apply in this context.
        schema.pop('readOnly', None)
        # enrich schema with additional info from filter_field
        enum = schema.pop('enum', None)
        # explicit filter choices may disable enum retrieved from model
        if not schema_from_override and filter_choices is not None:
            enum = filter_choices
        if enum:
            schema['enum'] = sorted(enum, key=str)

        description = schema.pop('description', None)
        if filter_field.extra.get('help_text', None):
            description = filter_field.extra['help_text']
        elif filter_field.label is not None:
            description = filter_field.label

        # parameter style variations based on filter base class
        if isinstance(filter_field, filters.BaseCSVFilter):
            schema = build_array_type(schema)
            field_names = [field_name]
            explode = False
            style = 'form'
        elif isinstance(filter_field, filters.MultipleChoiceFilter):
            schema = build_array_type(schema)
            field_names = [field_name]
            explode = True
            style = 'form'
        elif isinstance(filter_field, (filters.RangeFilter, filters.NumericRangeFilter)):
            try:
                suffixes = filter_field.field_class.widget.suffixes
            except AttributeError:
                suffixes = ['min', 'max']
            field_names = [
                f'{field_name}_{suffix}' if suffix else field_name for suffix in suffixes
            ]
            explode = None
            style = None
        else:
            field_names = [field_name]
            explode = None
            style = None

        return [
            build_parameter_type(
                name=field_name,
                required=filter_field.extra['required'],
                location=OpenApiParameter.QUERY,
                description=description,
                schema=schema,
                explode=explode,
                style=style
            )
            for field_name in field_names
        ]

    def _get_filter_method(self, filterset_class, filter_field):
        if callable(filter_field.method):
            return filter_field.method
        elif isinstance(filter_field.method, str):
            return getattr(filterset_class, filter_field.method)
        else:
            return None

    def _get_filter_method_hint(self, filter_method):
        try:
            return get_type_hints(filter_method)['value']
        except:  # noqa: E722
            return _NoHint

    def _get_explicit_filter_choices(self, filter_field):
        if 'choices' not in filter_field.extra:
            return None
        elif callable(filter_field.extra['choices']):
            # choices function may utilize the DB, so refrain from actually calling it.
            return []
        else:
            return [c for c, _ in filter_field.extra['choices']]

    def _get_model_field(self, filter_field, model):
        if not filter_field.field_name:
            return None
        path = filter_field.field_name.split('__')
        return follow_field_source(model, path, emit_warnings=False)

    def _get_schema_from_model_field(self, auto_schema, filter_field, model):
        # Has potential to throw exceptions. Needs to be wrapped in try/except!
        #
        # first search for the field in the model as this has the least amount of
        # potential side effects. Only after that fails, attempt to call
        # get_queryset() to check for potential query annotations.
        model_field = self._get_model_field(filter_field, model)
        if not isinstance(model_field, models.Field):
            qs = auto_schema.view.get_queryset()
            model_field = qs.query.annotations[filter_field.field_name].field
        return auto_schema._map_model_field(model_field, direction=None)

    # Taken from drf_yasg.inspectors.field.CamelCaseJSONFilter
    # def _is_camel_case(self, view):
    #     return any(
    #         issubclass(parser, CamelCaseJSONParser) for parser in view.parser_classes
    #     ) or any(
    #         issubclass(renderer, CamelCaseJSONRenderer)
    #         for renderer in view.renderer_classes
    #     )
    #
    # def _transform_query_params(self, view, query_params: QueryDict) -> QueryDict:
    #     if not self._is_camel_case(view):
    #         return query_params
    #
    #     # data can be a regular dict if it's coming from a serializer
    #     if hasattr(query_params, "lists"):
    #         data = dict(query_params.lists())
    #     else:
    #         data = query_params
    #
    #     transformed = underscoreize(data)
    #
    #     return QueryDict(urlencode(transformed, doseq=True))
    #
    # def get_filterset_kwargs(
    #     self, request: Request, queryset: models.QuerySet, view: APIView
    # ):
    #     """
    #     Get the initialization parameters for the filterset.
    #
    #     * filter on request.data if request.query_params is empty
    #     * do the camelCase transformation of filter parameters
    #     """
    #     kwargs = super().get_filterset_kwargs(request, queryset, view)
    #     filter_parameters = (
    #         request.query_params if not is_search_view(view) else request.data
    #     )
    #     query_params = self._transform_query_params(view, filter_parameters)
    #     kwargs["data"] = query_params
    #     return kwargs


class URLModelChoiceField(fields.ModelChoiceField):
    widget = URLInput

    def __init__(self, *args, **kwargs):
        self.instance_path = kwargs.pop("instance_path", None)
        super().__init__(*args, **kwargs)

    # Placeholder - gets replaced by URLModelChoiceFilter
    def _get_request(self):
        return None

    def url_to_pk(self, url: str):
        parsed = urlparse(url)
        path = parsed.path

        # this field only supports local FKs - so if we see a domain that does
        # not match the current host, this cannot possibly yield any results
        request = self._get_request()
        if request is not None:
            host = request.get_host()
            if parsed.netloc != host:
                raise NotAViewSet("External URL cannot map to a local viewset")

        instance = get_resource_for_path(path)
        if self.instance_path:
            for bit in self.instance_path.split("."):
                instance = getattr(instance, bit)
        model = self.queryset.model
        if not isinstance(instance, model):
            raise ValidationError(
                _("Invalid resource type supplied, expected %r") % model,
                code="invalid-type",
            )
        return instance.pk

    def to_python(self, value: str):
        if value is not None:
            URLValidator()(value)

        if value:
            try:
                value = self.url_to_pk(value)
            except NotAViewSet:
                logger.info("No %s found for URL %s", self.label, value)
                return FILTER_URL_DID_NOT_RESOLVE
            except models.ObjectDoesNotExist:
                logger.info("No %s found for URL %s", self.label, value)
                return FILTER_URL_DID_NOT_RESOLVE
        return super().to_python(value)


class URLModelChoiceFilter(filters.ModelChoiceFilter):
    field_class = URLModelChoiceField

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.instance_path = kwargs.get("instance_path", None)
        self.queryset = kwargs.get("queryset")

    @property
    def field(self):
        field = super().field
        # we need access to the request in the backing field...
        field._get_request = self.get_request
        return field

    def filter(self, qs, value):
        # If the URL did not resolve to an instance, return no results
        if value == FILTER_URL_DID_NOT_RESOLVE:
            return qs.none()
        return super().filter(qs, value)


class RSINFilter(filters.CharFilter):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("validators", [validate_rsin])
        super().__init__(*args, **kwargs)


class WildcardFilter(filters.CharFilter):
    """
    Filters the queryset based on a string and optionally allows wildcards in
    the query parameter.
    """

    wildcard = "*"

    def __init__(self, *args, **kwargs):
        kwargs["lookup_expr"] = "iregex"
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        if value in EMPTY_VALUES:
            return qs

        value = r"^{}$".format(value.replace(self.wildcard, ".*"))

        return super().filter(qs, value)

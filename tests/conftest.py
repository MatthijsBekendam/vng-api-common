from django.contrib.messages.middleware import MessageMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.urls import clear_script_prefix, set_script_prefix

import pytest


@pytest.fixture
def script_path(request):
    set_script_prefix("/some-prefix")
    request.addfinalizer(clear_script_prefix)


def dummy_get_response(request):
    raise NotImplementedError()


@pytest.fixture()
def request_with_middleware(rf):
    request = rf.get("/")
    SessionMiddleware(get_response=dummy_get_response).process_request(request)
    MessageMiddleware(get_response=dummy_get_response).process_request(request)
    return request

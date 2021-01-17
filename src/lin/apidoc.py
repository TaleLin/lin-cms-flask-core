import os
from functools import wraps
from uuid import uuid4

from flask import g, json
from pydantic import BaseModel as _BaseModel
from pydantic.main import Any, object_setattr, validate_model
from spectree import Response as _Response
from spectree import SpecTree as _SpecTree

from .config import global_config
from .db import Record, RecordCollection
from .exception import DocParameterError, ParameterError


class SpecTree(_SpecTree):
    def validate(
        self,
        query=None,
        json=None,
        headers=None,
        cookies=None,
        resp=None,
        tags=(),
        before=None,
        after=None,
    ):
        """
        - validate query, json, headers in request
        - validate response body and status code
        - add tags to this API route

        :param query: `pydantic.BaseModel`, query in uri like `?name=value`
        :param json: `pydantic.BaseModel`, JSON format request body
        :param headers: `pydantic.BaseModel`, if you have specific headers
        :param cookies: `pydantic.BaseModel`, if you have cookies for this route
        :param resp: `spectree.Response`
        :param tags: a tuple of tags string
        :param before: :meth:`spectree.utils.default_before_handler` for specific endpoint
        :param after: :meth:`spectree.utils.default_after_handler` for specific endpoint
        """

        resp_schema = resp.r

        def decorate_validation(func):
            @wraps(func)
            def validation(*args, **kwargs):
                def lin_before(req, resp, req_validation_error, instance):
                    g._resp_schema = resp_schema
                    if before:
                        before(req, resp, req_validation_error, instance)
                    schemas = ["headers", "cookies", "query", "json"]
                    for schema in schemas:
                        params = getattr(req.context, schema)
                        if params:
                            for k, v in params:
                                if hasattr(g, k):
                                    raise ParameterError(
                                        {
                                            k: "This parameter in {schema} needs to be renamed".format(
                                                schema=schema.capitalize()
                                            )
                                        }
                                    )
                                setattr(g, k, v)

                def lin_after(req, resp, req_validation_error, instance):
                    # global after handler here
                    if after:
                        after(req, resp, req_validation_error, instance)
                    elif self.after:
                        self.after(req, resp, req_validation_error, instance)

                return self.backend.validate(
                    func,
                    query,
                    json,
                    headers,
                    cookies,
                    resp,
                    lin_before,
                    lin_after,
                    *args,
                    **kwargs,
                )

            # register
            for name, model in zip(
                ("query", "json", "headers", "cookies"), (query, json, headers, cookies)
            ):
                if model is not None:
                    assert issubclass(model, BaseModel)
                    self.models[model.__name__] = model.schema(
                        ref_template="#/components/schemas/{model}"
                    )
                    setattr(validation, name, model.__name__)

            if resp:
                if query or json or headers or cookies:
                    resp.code_models[DocParameterError.code] = type(
                        "DocParameterErrorSchema",
                        (BaseModel,),
                        dict(
                            code=DocParameterError.message_code,
                            message=DocParameterError.message,
                        ),
                    )
                for model in resp.models:
                    self.models[model.__name__] = model.schema(
                        ref_template="#/components/schemas/{model}"
                    )
                validation.resp = resp

            if tags:
                validation.tags = tags

            # register decorator
            validation._decorator = self
            return validation

        return decorate_validation


doc_conf = dict(
    backend_name="flask",
    title="Lin-CMS API",
    mode="strict",
    version="0.3.0a8",
)
if os.getenv("FLASK_ENV", "production") == "production":
    # spectree 暂未提供关闭文档功能，production部署变更随机Url
    doc_conf.update({"path": "/".join(str(uuid4()).split("-"))})
api = SpecTree(**doc_conf)


class DocResponse(_Response):
    """
    response object

    :param args: subclass/object of APIException or obj/dict with code message_code message or None
    """

    def __init__(self, *args, r=None):
        self.code_models = dict()
        for arg in args:
            name = arg.__class__.__name__
            if name == "MultipleMeta":
                schema_name = arg.__name__ + "Schema"
            else:
                schema_name = "{class_name}_{message_code}_{hashmsg}Schema".format(
                    class_name=name,
                    message_code=arg.message_code,
                    hashmsg=hash((arg.message)),
                )

            self.code_models[arg.code] = type(
                schema_name,
                (BaseModel,),
                dict(code=arg.message_code, message=arg.message),
            )

        if r != None:
            http_status_code = 200
            if r.__class__.__name__ == "ModelMetaclass":
                self.code_models[http_status_code] = r
            elif isinstance(r, dict):
                from .encoder import JSONEncoder

                response_str = json.dumps(r, cls=JSONEncoder)
                r = type("Dict-{}Schema".format(hash(response_str)), (BaseModel,), r)
                self.code_models[http_status_code] = r
            elif isinstance(r, (RecordCollection, Record)) or (
                hasattr(r, "keys") and hasattr(r, "__getitem__")
            ):
                from .encoder import JSONEncoder

                r_str = json.dumps(r, cls=JSONEncoder)
                r = json.loads(r_str)
                r = type("Json{}Schema".format(hash(r_str)), (BaseModel,), r)
                self.code_models[http_status_code] = r
            self.r = r
        else:
            self.r = None

    def find_model(self, code):
        return self.code_models.get(code)

    def generate_spec(self):
        """
        generate the spec for responses

        :returns: JSON
        """
        responses = {}
        for code, base_model in self.code_models.items():
            responses[code] = {
                "description": global_config.get("DESC", dict()).get(code, "No Desc"),
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": f"#/components/schemas/{base_model.__name__}"
                        }
                    }
                },
            }

        return responses


class BaseModel(_BaseModel):
    def __init__(__pydantic_self__, **data: Any) -> None:
        values, fields_set, validation_error = validate_model(
            __pydantic_self__.__class__, data
        )
        if validation_error:
            # TODO 收集多个异常
            raise ParameterError(
                {i["loc"][-1]: [i["msg"]] for i in validation_error.errors()}
            )
        object_setattr(__pydantic_self__, "__dict__", values)
        object_setattr(__pydantic_self__, "__fields_set__", fields_set)
        __pydantic_self__._init_private_attributes()

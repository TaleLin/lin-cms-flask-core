"""
     core module of Lin.
     ~~~~~~~~~

     manager and main db models.

    :copyright: © 2020 by the Lin team.
    :license: MIT, see LICENSE for more details.
"""
import os
from collections import namedtuple
from datetime import date, datetime
from enum import Enum
from functools import wraps
from uuid import uuid4

from sqlalchemy.exc import DatabaseError
from pydantic import BaseModel as _BaseModel
from spectree import Response as _Response
from pydantic.main import Any ,object_setattr,validate_model

from flask import Blueprint, Flask, current_app, json, jsonify
from flask.json import JSONEncoder as _JSONEncoder
from flask.wrappers import Response
from werkzeug.exceptions import HTTPException
from werkzeug.local import LocalProxy


from .config import global_config
from .db import Record, RecordCollection, db
from .exception import APIException, InternalServerError, ParameterError
from .jwt import jwt
from .manager import Manager
from .syslogger import SysLogger



__version__ = "0.3.0"

# 路由函数的权限和模块信息(meta信息)
Meta = namedtuple("meta", ["auth", "module", "mount"])

#       -> endpoint -> func
# auth                      -> module
#       -> endpoint -> func

# 记录路由函数的权限和模块信息
permission_meta_infos = {}

# config for Lin plugins
# we always access config by flask, but it dependents on the flask context
# so we move the plugin config here,which you can access config more convenience


# a proxy for manager instance
# attention, only used when context in  stack

# 获得manager实例
# 注意，仅仅在flask的上下文栈中才可获得
manager: Manager = LocalProxy(lambda: get_manager())


def get_manager():
    _manager = current_app.extensions["manager"]
    if _manager:
        return _manager
    else:
        app = current_app._get_current_object()
        with app.app_context():
            return app.extensions["manager"]


def permission_meta(auth, module="common", mount=True):
    """
    记录路由函数的信息
    记录路由函数访问的推送信息模板
    注：只有使用了 permission_meta 装饰器的函数才会被记录到权限管理的map中
    :param auth: 权限
    :param module: 所属模块
    :param mount: 是否挂在到权限中（一些视图函数需要说明，或暂时决定不挂在到权限中，则设置为False）
    :return:
    """

    def wrapper(func):
        name = func.__name__ + str(func.__hash__())
        existed = (
            permission_meta_infos.get(name, None)
            and permission_meta_infos.get(name).module == module
        )
        if existed:
            raise Exception("func's name cant't be repeat in a same module")
        else:
            permission_meta_infos.setdefault(name, Meta(auth, module, mount))
        return func

    return wrapper


def find_user(**kwargs):
    return manager.find_user(**kwargs)


def find_group(**kwargs):
    return manager.find_group(**kwargs)


def find_group_ids_by_user_id(user_id):
    return manager.find_group_ids_by_user_id(user_id)


def get_ep_infos():
    """ 返回权限管理中的所有视图函数的信息，包含它所属module """
    return manager.get_ep_infos()


def find_info_by_ep(ep):
    """ 通过请求的endpoint寻找路由函数的meta信息"""
    return manager.find_info_by_ep(ep)


def is_user_allowed(group_ids):
    return manager.is_user_allowed(group_ids)


def find_auth_module(auth):
    """ 通过权限寻找meta信息"""
    return manager.find_auth_module(auth)

class BaseModel(_BaseModel):

    def __init__(__pydantic_self__, **data: Any) -> None:
        values, fields_set, validation_error = validate_model(__pydantic_self__.__class__, data)
        if validation_error:
            # TODO 收集多个异常
            raise ParameterError(
                {i["loc"][0]: [i["msg"]] for i in validation_error.errors()}
                                   )
        object_setattr(__pydantic_self__, '__dict__', values)
        object_setattr(__pydantic_self__, '__fields_set__', fields_set)
        __pydantic_self__._init_private_attributes()


class DocResponse(_Response):
    """
    response object

    :param args: subclass/object of APIException or obj/dict with code message_code message or None
    :param kwargs: <HTTP status code>: <`dict`> <`Record`> <`RecordCollection`> <`pydantic.BaseModel`> or None
    """

    def __init__(self, *args, **kwargs):
        self.code_models = dict()

        for arg in args:
            name = arg.__class__.__name__
            if name == "MultipleMeta":
                schema_name = arg.__name__ + "Schema"
            else:
                schema_name = "{class_name}_{message_code}_{hashmsg}Schema".format(
                    class_name=name,
                    message_code=arg.message_code, 
                    hashmsg=hash((arg.message))
                )

            self.code_models[arg.code]  = type(
                schema_name,
                (BaseModel,), 
                dict(code=arg.message_code , message=arg.message)
            )

        for http_status, response in kwargs.items():
            http_status_code = int(http_status.split('_')[-1])
            if response.__class__.__name__ == "ModelMetaclass":
                self.code_models[http_status_code]  = response
            elif isinstance(response, dict):
                response_str = json.dumps(response, cls=JSONEncoder)
                self.code_models[http_status_code]  = type(
                    "Dict-{}Schema".format(hash(response_str)),
                    (BaseModel,),
                    response 
                    )
            elif isinstance(response, (RecordCollection, Record)) or (
                hasattr(response, "keys") and hasattr(response, "__getitem__")
            ):
                response_str = json.dumps(response, cls=JSONEncoder)
                response = json.loads(response_str)
                self.code_models[http_status_code]  = type(
                    'Json{}Schema'.format(hash(response_str)),
                    (BaseModel,),
                    response
                    )

    def generate_spec(self):
        """
        generate the spec for responses

        :returns: JSON
        """
        responses = {}
        for code, base_model in self.code_models.items():
            responses[code] = {
                "description": global_config.get("DESC", None).get(code,"No Desc" ),
                "content": {
                    "application/json": {
                        "schema": {"$ref": f"#/components/schemas/{base_model.__name__}"}
                    }
                },
            }

        return responses

class JSONEncoder(_JSONEncoder):
    def default(self, o):
        if o.__class__.__name__ == "ModelMetaclass":
            base_model_dict = dict()
            for k, v in o.__fields__.items():
                base_model_dict[k] = getattr(o, k) if hasattr(o, k) else v.default
            return base_model_dict
        if hasattr(o, "keys") and hasattr(o, "__getitem__"):
            return dict(o)
        if isinstance(o, datetime):
            return o.strftime("%Y-%m-%dT%H:%M:%SZ")
        if isinstance(o, date):
            return o.strftime("%Y-%m-%d")
        if isinstance(o, Enum):
            return o.value
        if isinstance(o, (RecordCollection, Record)):
            return o.as_dict()
        if isinstance(o, BaseModel):
            return o.dict()
        if isinstance(o, (int, list, set, tuple)):
            return json.dumps(o, cls=JSONEncoder)
        return JSONEncoder.default(self, o)


def auto_response(func):
    @wraps(func)
    def make_lin_response(o):
        if isinstance(o, (RecordCollection, Record, BaseModel)) or (
            hasattr(o, "keys") and hasattr(o, "__getitem__")) or (
                o.__class__.__name__ == "ModelMetaclass"):
            o = jsonify(o)
        elif isinstance(o, (Enum, int, list, set)):
            o = json.dumps(o)
        elif isinstance(o, tuple) and not isinstance(o[0], Response):
            oc = list(o)
            oc[0] = json.dumps(o[0])
            o = tuple(oc)

        return func(o)

    return make_lin_response


class Lin(object):
    def __init__(
        self,
        app: Flask = None,  # flask app , default None
        group_model=None,  # group model, default None
        user_model=None,  # user model, default None
        identity_model=None,  # user identity model,default None
        permission_model=None,  # permission model, default None
        group_permission_model=None,  # group permission 多对多关联模型
        user_group_model=None,  # user group 多对多关联模型
        jsonencoder=None,  # 序列化器
        sync_permissions=True,  # create db table if not exist and sync permissions, default True
        mount=True,  # 是否挂载默认的蓝图, default True
        handle=True,  # 是否使用全局异常处理, default True
        syslogger=True,  # 是否使用自定义系统运行日志，default True
        **kwargs         #  保留的扩展参数
    ):
        global global_config
        for k, v in kwargs.items():
            if k.startswith("config_"):
                global_config[k[7:]] = v
        self.app = app
        if app is not None:
            self.init_app(
                app,
                group_model,
                user_model,
                identity_model,
                permission_model,
                group_permission_model,
                user_group_model,
                jsonencoder,
                sync_permissions,
                mount,
                handle,
                syslogger,
            )

    def init_app(
        self,
        app,
        group_model=None,
        user_model=None,
        identity_model=None,
        permission_model=None,
        group_permission_model=None,
        user_group_model=None,
        jsonencoder=None,
        sync_permissions=True,
        mount=True,
        handle=True,
        syslogger=True,
    ):
        # load default lin db model if None
        if not group_model:
            from .model import Group

            group_model = Group
        if not user_model:
            from .model import User

            self.user_model = User
        if not permission_model:
            from .model import Permission

            permission_model = Permission
        if not group_permission_model:
            from .model import GroupPermission

            group_permission_model = GroupPermission
        if not user_group_model:
            from .model import UserGroup

            user_group_model = UserGroup
        if not identity_model:
            from .model import UserIdentity

            identity_model = UserIdentity
        # 默认蓝图的前缀
        app.config.setdefault("BP_URL_PREFIX", "/plugin")
        # 文件上传配置未指定时的默认值
        app.config.setdefault(
            "FILE",
            {
                "STORE_DIR": "app/assets",
                "SINGLE_LIMIT": 1024 * 1024 * 2,
                "TOTAL_LIMIT": 1024 * 1024 * 20,
                "NUMS": 10,
                "INCLUDE": set(["jpg", "png", "jpeg"]),
                "EXCLUDE": set([]),
            },
        )
        self.jsonencoder = jsonencoder
        self.enable_auto_jsonify(app)
        self.app = app
        # 初始化 manager
        self.manager = Manager(
            app.config.get("PLUGIN_PATH", dict()),
            group_model=group_model,
            user_model=user_model,
            identity_model=identity_model,
            permission_model=permission_model,
            group_permission_model=group_permission_model,
            user_group_model=user_group_model,
        )
        self.app.extensions["manager"] = self.manager
        db.init_app(app)
        jwt.init_app(app)
        mount and self.mount(app)
        # 挂载后才能获取代码中的权限
        # 多进程/线程下可能同时写入相同数据，由权限表联合唯一约束限制
        try:
            sync_permissions and self.sync_permissions(app)
        except DatabaseError:
            pass
        handle and self.handle_error(app)
        syslogger and SysLogger(app)

    def sync_permissions(self, app):
        with app.app_context():
            self.manager.sync_permissions()

    def mount(self, app):
        # 加载默认插件路由
        bp = Blueprint("plugin", __name__)
        # 加载插件的路由
        for plugin in self.manager.plugins.values():
            if len(plugin.controllers.values()) > 1:
                for controller in plugin.controllers.values():
                    controller.register(bp, url_prefix="/" + plugin.name)
            else:
                for controller in plugin.controllers.values():
                    controller.register(bp)
        app.register_blueprint(
            bp, url_prefix=app.config.get("BP_URL_PREFIX", "/plugins")
        )
        for ep, func in app.view_functions.items():
            info = permission_meta_infos.get(
                func.__name__ + str(func.__hash__()), None)
            if info:
                self.manager.ep_meta.setdefault(ep, info)

    def handle_error(self, app):
        @app.errorhandler(Exception)
        def handler(e):
            if isinstance(e, APIException):
                return e
            if isinstance(e, HTTPException):
                code = e.code
                message = e.description
                message_code = 20000
                return APIException(message_code, message).set_code(code)
            else:
                if not app.config["DEBUG"]:
                    import traceback

                    app.logger.error(traceback.format_exc())
                    return InternalServerError()
                else:
                    raise e

    def enable_auto_jsonify(self, app):
        app.json_encoder = self.jsonencoder or JSONEncoder
        app.make_response = auto_response(app.make_response)

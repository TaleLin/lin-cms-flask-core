"""
    MultipleMeta of Lin
    ~~~~~~~~~

    :copyright: © 2020 by the Lin team.
    :license: MIT, see LICENSE for more details.
"""
import inspect
import types

__all__ = ["MultipleMeta"]


class MultiMethod:
    def __init__(self, name):
        self._methods = {}
        self.__name__ = name

    def register(self, meth):
        """
        根据方法参数类型注册一个新方法
        """
        sig = inspect.signature(meth)

        # 用于保存方法参数的类型
        types = []
        for name, parm in sig.parameters.items():
            # 忽略self
            if name == "self":
                continue
            if parm.annotation is inspect.Parameter.empty:
                raise TypeError("参数 {} 必须使用类型注释".format(name))
            if not isinstance(parm.annotation, type):
                raise TypeError("参数 {} 的注解必须是数据类型".format(name))
            if parm.default is not inspect.Parameter.empty:
                self._methods[tuple(types)] = meth
            types.append(parm.annotation)

        self._methods[tuple(types)] = meth

    # 当调用MyOverload类中的某个方法时，会执行__call__方法，在该方法中通过参数类型注解检测具体的方法实例，然后调用并返回执行结果

    def __call__(self, *args):
        """
        使用新的标识表用方法
        """
        types = tuple(type(arg) for arg in args[1:])
        meth = self._methods.get(types, None)
        if meth:
            return meth(*args)
        else:
            raise TypeError("No matching method for types {}".format(types))

    def __get__(self, instance, cls):
        if instance is not None:
            return types.MethodType(self, instance)
        else:
            return self


class MultiDict(dict):
    def __setitem__(self, key, value):
        if key in self:
            # 如果key存在, 一定是MultiMethod类型或可调用的方法
            current_value = self[key]
            if isinstance(current_value, MultiMethod):
                current_value.register(value)
            else:
                mvalue = MultiMethod(key)
                mvalue.register(current_value)
                mvalue.register(value)
                super().__setitem__(key, mvalue)
        else:
            super().__setitem__(key, value)


class MultipleMeta(type):
    # 任何类只要使用MultileMeta，就可以支持方法重载
    def __new__(cls, clsname, bases, clsdict):
        return type.__new__(cls, clsname, bases, dict(clsdict))

    @classmethod
    def __prepare__(cls, clsname, bases):
        return MultiDict()

'''
# Constructs

> Software-defined persistent state

![Release](https://github.com/aws/constructs/workflows/Release/badge.svg)
[![npm version](https://badge.fury.io/js/constructs.svg)](https://badge.fury.io/js/constructs)
[![PyPI version](https://badge.fury.io/py/constructs.svg)](https://badge.fury.io/py/constructs)
[![NuGet version](https://badge.fury.io/nu/Constructs.svg)](https://badge.fury.io/nu/Constructs)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/software.constructs/constructs/badge.svg?style=plastic)](https://maven-badges.herokuapp.com/maven-central/software.constructs/constructs)

## What are constructs?

Constructs are classes which define a "piece of system state". Constructs can be composed together to form higher-level building blocks which represent more complex state.

Constructs are often used to represent the *desired state* of cloud applications. For example, in the AWS CDK, which is used to define the desired state for AWS infrastructure using CloudFormation, the lowest-level construct represents a *resource definition* in a CloudFormation template. These resources are composed to represent higher-level logical units of a cloud application, etc.

## Contributing

This project has adopted the [Amazon Open Source Code of
Conduct](https://aws.github.io/code-of-conduct).

We welcome community contributions and pull requests. See our [contribution
guide](./CONTRIBUTING.md) for more information on how to report issues, set up a
development environment and submit code.

## License

This project is distributed under the [Apache License, Version 2.0](./LICENSE).
'''
import abc
import builtins
import datetime
import enum
import typing

import jsii
import publication
import typing_extensions

from ._jsii import *


@jsii.enum(jsii_type="constructs.ConstructOrder")
class ConstructOrder(enum.Enum):
    '''In what order to return constructs.'''

    PREORDER = "PREORDER"
    '''Depth-first, pre-order.'''
    POSTORDER = "POSTORDER"
    '''Depth-first, post-order (leaf nodes first).'''


class Dependable(metaclass=jsii.JSIIAbstractClass, jsii_type="constructs.Dependable"):
    '''(experimental) Trait for IDependable.

    Traits are interfaces that are privately implemented by objects. Instead of
    showing up in the public interface of a class, they need to be queried
    explicitly. This is used to implement certain framework features that are
    not intended to be used by Construct consumers, and so should be hidden
    from accidental use.

    :stability: experimental

    Example::

        // Usage
        const roots = DependableTrait.get(construct).dependencyRoots;
        
        // Definition
        DependableTrait.implement(construct, {
          get dependencyRoots() { return []; }
        });
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="get") # type: ignore[misc]
    @builtins.classmethod
    def get(cls, instance: "IDependable") -> "Dependable":
        '''(deprecated) Return the matching Dependable for the given class instance.

        :param instance: -

        :deprecated: use ``of``

        :stability: deprecated
        '''
        return typing.cast("Dependable", jsii.sinvoke(cls, "get", [instance]))

    @jsii.member(jsii_name="implement") # type: ignore[misc]
    @builtins.classmethod
    def implement(cls, instance: "IDependable", trait: "Dependable") -> None:
        '''(experimental) Turn any object into an IDependable.

        :param instance: -
        :param trait: -

        :stability: experimental
        '''
        return typing.cast(None, jsii.sinvoke(cls, "implement", [instance, trait]))

    @jsii.member(jsii_name="of") # type: ignore[misc]
    @builtins.classmethod
    def of(cls, instance: "IDependable") -> "Dependable":
        '''(experimental) Return the matching Dependable for the given class instance.

        :param instance: -

        :stability: experimental
        '''
        return typing.cast("Dependable", jsii.sinvoke(cls, "of", [instance]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dependencyRoots")
    @abc.abstractmethod
    def dependency_roots(self) -> typing.List["IConstruct"]:
        '''(experimental) The set of constructs that form the root of this dependable.

        All resources under all returned constructs are included in the ordering
        dependency.

        :stability: experimental
        '''
        ...


class _DependableProxy(Dependable):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dependencyRoots")
    def dependency_roots(self) -> typing.List["IConstruct"]:
        '''(experimental) The set of constructs that form the root of this dependable.

        All resources under all returned constructs are included in the ordering
        dependency.

        :stability: experimental
        '''
        return typing.cast(typing.List["IConstruct"], jsii.get(self, "dependencyRoots"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, Dependable).__jsii_proxy_class__ = lambda : _DependableProxy


@jsii.interface(jsii_type="constructs.IDependable")
class IDependable(typing_extensions.Protocol):
    '''Trait marker for classes that can be depended upon.

    The presence of this interface indicates that an object has
    an ``IDependableTrait`` implementation.

    This interface can be used to take an (ordering) dependency on a set of
    constructs. An ordering dependency implies that the resources represented by
    those constructs are deployed before the resources depending ON them are
    deployed.
    '''

    pass


class _IDependableProxy:
    '''Trait marker for classes that can be depended upon.

    The presence of this interface indicates that an object has
    an ``IDependableTrait`` implementation.

    This interface can be used to take an (ordering) dependency on a set of
    constructs. An ordering dependency implies that the resources represented by
    those constructs are deployed before the resources depending ON them are
    deployed.
    '''

    __jsii_type__: typing.ClassVar[str] = "constructs.IDependable"
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IDependable).__jsii_proxy_class__ = lambda : _IDependableProxy


@jsii.interface(jsii_type="constructs.IValidation")
class IValidation(typing_extensions.Protocol):
    '''Implement this interface in order for the construct to be able to validate itself.

    Implement this interface in order for the construct to be able to validate itself.
    '''

    @jsii.member(jsii_name="validate")
    def validate(self) -> typing.List[builtins.str]:
        '''Validate the current construct.

        This method can be implemented by derived constructs in order to perform
        validation logic. It is called on all constructs before synthesis.
        Validate the current construct.

        This method can be implemented by derived constructs in order to perform
        validation logic. It is called on all constructs before synthesis.

        :return: An array of validation error messages, or an empty array if there the construct is valid.
        '''
        ...


class _IValidationProxy:
    '''Implement this interface in order for the construct to be able to validate itself.

    Implement this interface in order for the construct to be able to validate itself.
    '''

    __jsii_type__: typing.ClassVar[str] = "constructs.IValidation"

    @jsii.member(jsii_name="validate")
    def validate(self) -> typing.List[builtins.str]:
        '''Validate the current construct.

        This method can be implemented by derived constructs in order to perform
        validation logic. It is called on all constructs before synthesis.
        Validate the current construct.

        This method can be implemented by derived constructs in order to perform
        validation logic. It is called on all constructs before synthesis.

        :return: An array of validation error messages, or an empty array if there the construct is valid.
        '''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validate", []))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IValidation).__jsii_proxy_class__ = lambda : _IValidationProxy


@jsii.data_type(
    jsii_type="constructs.MetadataEntry",
    jsii_struct_bases=[],
    name_mapping={"data": "data", "type": "type", "trace": "trace"},
)
class MetadataEntry:
    def __init__(
        self,
        *,
        data: typing.Any,
        type: builtins.str,
        trace: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''An entry in the construct metadata table.

        :param data: The data.
        :param type: The metadata entry type.
        :param trace: Stack trace at the point of adding the metadata. Only available if ``addMetadata()`` is called with ``stackTrace: true``. Default: - no trace information
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "data": data,
            "type": type,
        }
        if trace is not None:
            self._values["trace"] = trace

    @builtins.property
    def data(self) -> typing.Any:
        '''The data.'''
        result = self._values.get("data")
        assert result is not None, "Required property 'data' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def type(self) -> builtins.str:
        '''The metadata entry type.'''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def trace(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Stack trace at the point of adding the metadata.

        Only available if ``addMetadata()`` is called with ``stackTrace: true``.

        :default: - no trace information
        '''
        result = self._values.get("trace")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "MetadataEntry(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="constructs.MetadataOptions",
    jsii_struct_bases=[],
    name_mapping={
        "stack_trace": "stackTrace",
        "trace_from_function": "traceFromFunction",
    },
)
class MetadataOptions:
    def __init__(
        self,
        *,
        stack_trace: typing.Optional[builtins.bool] = None,
        trace_from_function: typing.Any = None,
    ) -> None:
        '''Options for ``construct.addMetadata()``.

        :param stack_trace: Include stack trace with metadata entry. Default: false
        :param trace_from_function: A JavaScript function to begin tracing from. This option is ignored unless ``stackTrace`` is ``true``. Default: addMetadata()
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if stack_trace is not None:
            self._values["stack_trace"] = stack_trace
        if trace_from_function is not None:
            self._values["trace_from_function"] = trace_from_function

    @builtins.property
    def stack_trace(self) -> typing.Optional[builtins.bool]:
        '''Include stack trace with metadata entry.

        :default: false
        '''
        result = self._values.get("stack_trace")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def trace_from_function(self) -> typing.Any:
        '''A JavaScript function to begin tracing from.

        This option is ignored unless ``stackTrace`` is ``true``.

        :default: addMetadata()
        '''
        result = self._values.get("trace_from_function")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "MetadataOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Node(metaclass=jsii.JSIIMeta, jsii_type="constructs.Node"):
    '''Represents the construct node in the scope tree.'''

    def __init__(
        self,
        host: "Construct",
        scope: "IConstruct",
        id: builtins.str,
    ) -> None:
        '''
        :param host: -
        :param scope: -
        :param id: -
        '''
        jsii.create(self.__class__, self, [host, scope, id])

    @jsii.member(jsii_name="of") # type: ignore[misc]
    @builtins.classmethod
    def of(cls, construct: "IConstruct") -> "Node":
        '''(deprecated) Returns the node associated with a construct.

        :param construct: the construct.

        :deprecated: use ``construct.node`` instead

        :stability: deprecated
        '''
        return typing.cast("Node", jsii.sinvoke(cls, "of", [construct]))

    @jsii.member(jsii_name="addDependency")
    def add_dependency(self, *deps: IDependable) -> None:
        '''Add an ordering dependency on another construct.

        An ``IDependable``

        :param deps: -
        '''
        return typing.cast(None, jsii.invoke(self, "addDependency", [*deps]))

    @jsii.member(jsii_name="addMetadata")
    def add_metadata(
        self,
        type: builtins.str,
        data: typing.Any,
        *,
        stack_trace: typing.Optional[builtins.bool] = None,
        trace_from_function: typing.Any = None,
    ) -> None:
        '''Adds a metadata entry to this construct.

        Entries are arbitrary values and will also include a stack trace to allow tracing back to
        the code location for when the entry was added. It can be used, for example, to include source
        mapping in CloudFormation templates to improve diagnostics.

        :param type: a string denoting the type of metadata.
        :param data: the value of the metadata (can be a Token). If null/undefined, metadata will not be added.
        :param stack_trace: Include stack trace with metadata entry. Default: false
        :param trace_from_function: A JavaScript function to begin tracing from. This option is ignored unless ``stackTrace`` is ``true``. Default: addMetadata()
        '''
        options = MetadataOptions(
            stack_trace=stack_trace, trace_from_function=trace_from_function
        )

        return typing.cast(None, jsii.invoke(self, "addMetadata", [type, data, options]))

    @jsii.member(jsii_name="addValidation")
    def add_validation(self, validation: IValidation) -> None:
        '''Adds a validation to this construct.

        When ``node.validate()`` is called, the ``validate()`` method will be called on
        all validations and all errors will be returned.

        :param validation: The validation object.
        '''
        return typing.cast(None, jsii.invoke(self, "addValidation", [validation]))

    @jsii.member(jsii_name="findAll")
    def find_all(
        self,
        order: typing.Optional[ConstructOrder] = None,
    ) -> typing.List["IConstruct"]:
        '''Return this construct and all of its children in the given order.

        :param order: -
        '''
        return typing.cast(typing.List["IConstruct"], jsii.invoke(self, "findAll", [order]))

    @jsii.member(jsii_name="findChild")
    def find_child(self, id: builtins.str) -> "IConstruct":
        '''Return a direct child by id.

        Throws an error if the child is not found.

        :param id: Identifier of direct child.

        :return: Child with the given id.
        '''
        return typing.cast("IConstruct", jsii.invoke(self, "findChild", [id]))

    @jsii.member(jsii_name="lock")
    def lock(self) -> None:
        '''Locks this construct from allowing more children to be added.

        After this
        call, no more children can be added to this construct or to any children.
        '''
        return typing.cast(None, jsii.invoke(self, "lock", []))

    @jsii.member(jsii_name="setContext")
    def set_context(self, key: builtins.str, value: typing.Any) -> None:
        '''This can be used to set contextual values.

        Context must be set before any children are added, since children may consult context info during construction.
        If the key already exists, it will be overridden.

        :param key: The context key.
        :param value: The context value.
        '''
        return typing.cast(None, jsii.invoke(self, "setContext", [key, value]))

    @jsii.member(jsii_name="tryFindChild")
    def try_find_child(self, id: builtins.str) -> typing.Optional["IConstruct"]:
        '''Return a direct child by id, or undefined.

        :param id: Identifier of direct child.

        :return: the child if found, or undefined
        '''
        return typing.cast(typing.Optional["IConstruct"], jsii.invoke(self, "tryFindChild", [id]))

    @jsii.member(jsii_name="tryGetContext")
    def try_get_context(self, key: builtins.str) -> typing.Any:
        '''Retrieves a value from tree context.

        Context is usually initialized at the root, but can be overridden at any point in the tree.

        :param key: The context key.

        :return: The context value or ``undefined`` if there is no context value for thie key.
        '''
        return typing.cast(typing.Any, jsii.invoke(self, "tryGetContext", [key]))

    @jsii.member(jsii_name="tryRemoveChild")
    def try_remove_child(self, child_name: builtins.str) -> builtins.bool:
        '''(experimental) Remove the child with the given name, if present.

        :param child_name: -

        :return: Whether a child with the given name was deleted.

        :stability: experimental
        '''
        return typing.cast(builtins.bool, jsii.invoke(self, "tryRemoveChild", [child_name]))

    @jsii.member(jsii_name="validate")
    def validate(self) -> typing.List[builtins.str]:
        '''Validates this construct.

        Invokes the ``validate()`` method on all validations added through
        ``addValidation()``.

        :return:

        an array of validation error messages associated with this
        construct.
        '''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validate", []))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="PATH_SEP")
    def PATH_SEP(cls) -> builtins.str:
        '''Separator used to delimit construct path components.'''
        return typing.cast(builtins.str, jsii.sget(cls, "PATH_SEP"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="addr")
    def addr(self) -> builtins.str:
        '''Returns an opaque tree-unique address for this construct.

        Addresses are 42 characters hexadecimal strings. They begin with "c8"
        followed by 40 lowercase hexadecimal characters (0-9a-f).

        Addresses are calculated using a SHA-1 of the components of the construct
        path.

        To enable refactorings of construct trees, constructs with the ID ``Default``
        will be excluded from the calculation. In those cases constructs in the
        same tree may have the same addreess.

        Example::

            c83a2846e506bcc5f10682b564084bca2d275709ee
        '''
        return typing.cast(builtins.str, jsii.get(self, "addr"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="children")
    def children(self) -> typing.List["IConstruct"]:
        '''All direct children of this construct.'''
        return typing.cast(typing.List["IConstruct"], jsii.get(self, "children"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dependencies")
    def dependencies(self) -> typing.List["IConstruct"]:
        '''Return all dependencies registered on this node (non-recursive).'''
        return typing.cast(typing.List["IConstruct"], jsii.get(self, "dependencies"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="id")
    def id(self) -> builtins.str:
        '''The id of this construct within the current scope.

        This is a a scope-unique id. To obtain an app-unique id for this construct, use ``addr``.
        '''
        return typing.cast(builtins.str, jsii.get(self, "id"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="locked")
    def locked(self) -> builtins.bool:
        '''Returns true if this construct or the scopes in which it is defined are locked.'''
        return typing.cast(builtins.bool, jsii.get(self, "locked"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="metadata")
    def metadata(self) -> typing.List[MetadataEntry]:
        '''An immutable array of metadata objects associated with this construct.

        This can be used, for example, to implement support for deprecation notices, source mapping, etc.
        '''
        return typing.cast(typing.List[MetadataEntry], jsii.get(self, "metadata"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="path")
    def path(self) -> builtins.str:
        '''The full, absolute path of this construct in the tree.

        Components are separated by '/'.
        '''
        return typing.cast(builtins.str, jsii.get(self, "path"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="root")
    def root(self) -> "IConstruct":
        '''Returns the root of the construct tree.

        :return: The root of the construct tree.
        '''
        return typing.cast("IConstruct", jsii.get(self, "root"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scopes")
    def scopes(self) -> typing.List["IConstruct"]:
        '''All parent scopes of this construct.

        :return:

        a list of parent scopes. The last element in the list will always
        be the current construct and the first element will be the root of the
        tree.
        '''
        return typing.cast(typing.List["IConstruct"], jsii.get(self, "scopes"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scope")
    def scope(self) -> typing.Optional["IConstruct"]:
        '''Returns the scope in which this construct is defined.

        The value is ``undefined`` at the root of the construct scope tree.
        '''
        return typing.cast(typing.Optional["IConstruct"], jsii.get(self, "scope"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultChild")
    def default_child(self) -> typing.Optional["IConstruct"]:
        '''Returns the child construct that has the id ``Default`` or ``Resource"``.

        This is usually the construct that provides the bulk of the underlying functionality.
        Useful for modifications of the underlying construct that are not available at the higher levels.
        Override the defaultChild property.

        This should only be used in the cases where the correct
        default child is not named 'Resource' or 'Default' as it
        should be.

        If you set this to undefined, the default behavior of finding
        the child named 'Resource' or 'Default' will be used.

        :return: a construct or undefined if there is no default child

        :throws: if there is more than one child
        '''
        return typing.cast(typing.Optional["IConstruct"], jsii.get(self, "defaultChild"))

    @default_child.setter
    def default_child(self, value: typing.Optional["IConstruct"]) -> None:
        jsii.set(self, "defaultChild", value)


@jsii.implements(IDependable)
class DependencyGroup(metaclass=jsii.JSIIMeta, jsii_type="constructs.DependencyGroup"):
    '''(experimental) A set of constructs to be used as a dependable.

    This class can be used when a set of constructs which are disjoint in the
    construct tree needs to be combined to be used as a single dependable.

    :stability: experimental
    '''

    def __init__(self, *deps: IDependable) -> None:
        '''
        :param deps: -

        :stability: experimental
        '''
        jsii.create(self.__class__, self, [*deps])

    @jsii.member(jsii_name="add")
    def add(self, *scopes: IDependable) -> None:
        '''(experimental) Add a construct to the dependency roots.

        :param scopes: -

        :stability: experimental
        '''
        return typing.cast(None, jsii.invoke(self, "add", [*scopes]))


@jsii.interface(jsii_type="constructs.IConstruct")
class IConstruct(IDependable, typing_extensions.Protocol):
    '''Represents a construct.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="node")
    def node(self) -> Node:
        '''The tree node.'''
        ...


class _IConstructProxy(
    jsii.proxy_for(IDependable) # type: ignore[misc]
):
    '''Represents a construct.'''

    __jsii_type__: typing.ClassVar[str] = "constructs.IConstruct"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="node")
    def node(self) -> Node:
        '''The tree node.'''
        return typing.cast(Node, jsii.get(self, "node"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IConstruct).__jsii_proxy_class__ = lambda : _IConstructProxy


@jsii.implements(IConstruct)
class Construct(metaclass=jsii.JSIIMeta, jsii_type="constructs.Construct"):
    '''Represents the building block of the construct graph.

    All constructs besides the root construct must be created within the scope of
    another construct.
    '''

    def __init__(self, scope: "Construct", id: builtins.str) -> None:
        '''Creates a new construct node.

        :param scope: The scope in which to define this construct.
        :param id: The scoped construct ID. Must be unique amongst siblings. If the ID includes a path separator (``/``), then it will be replaced by double dash ``--``.
        '''
        jsii.create(self.__class__, self, [scope, id])

    @jsii.member(jsii_name="isConstruct") # type: ignore[misc]
    @builtins.classmethod
    def is_construct(cls, x: typing.Any) -> builtins.bool:
        '''(deprecated) Checks if ``x`` is a construct.

        :param x: Any object.

        :return: true if ``x`` is an object created from a class which extends ``Construct``.

        :deprecated: use ``x instanceof Construct`` instead

        :stability: deprecated
        '''
        return typing.cast(builtins.bool, jsii.sinvoke(cls, "isConstruct", [x]))

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Returns a string representation of this construct.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="node")
    def node(self) -> Node:
        '''The tree node.'''
        return typing.cast(Node, jsii.get(self, "node"))


__all__ = [
    "Construct",
    "ConstructOrder",
    "Dependable",
    "DependencyGroup",
    "IConstruct",
    "IDependable",
    "IValidation",
    "MetadataEntry",
    "MetadataOptions",
    "Node",
]

publication.publish()

# CMake Build System

Bareflank and [its extensions](https://github.com/bareflank/boxy.git) use
CMake to build each component. This document provides some explanation
of how the CMake buildsystem works and how to use it in your own extension.

## Design

The Bareflank buildsystem implements a superbuild pattern. The top-level
[CMakeLists.txt](../CMakeLists.txt) is what drives the build of the `project()`s
underneath it (i.e., in this repo) along with any defined in external extensions
(extensions will be discussed later, for now just think of it as a CMake project
that is Bareflank "aware").

### Superbuild

Typically, CMake buildsystems do one call to `project()` in the root CMakeLists.txt
file and tend to organize targets such that their structure mirrors
the layout of the repo. Bareflank also follows this pattern, but instead of
adding targets to one root project, each component (i.e. library or executable)
is its own project that is added to the superbuild with `ExternalProject_Add()`.

> Note that even though there aren't any calls to `ExternalProject_Add`
  in [CMakeLists.txt](../CMakeLists.txt), the helper macro `add_subproject` calls
  it internally.

The reason projects are used is that Bareflank requires different toolchains to
build the VMM, tests, and userspace components, and CMake does not support
building two targets in a project with two different toolchains. In other
words, there can only be *one* toolchain per project. On the other hand,
`ExternalProject_Add` creates a new CMake process and can pass any
configuration variables to that process. So whenever the superbuild
`ExternalProject_Add()`s a project, it specifies (among other things) the
toolchain file that CMake should use.

Once an external project is added, the standard targets made available via
`ExternalProject_Add`. The superbuild uses these targets to specify dependencies
between projects.

### Target propagation

The main disadvantage of the superbuild approach is that the projects become
isolated from each other. Targets defined in one project have no knowledge of
targets defined in a different project, which is bad because they still depend on
one another (e.g., `bfvmm` depends on `bfintrinsics` and `bfutil` even though
they are distinct CMake projects). Also all the target\_\* commands that
specify usage requirements only work within the project they are called.

Bareflank overcomes this issue by exporting the targets of each project to a
common location. Any downstream project that includes the target export files
has access to *every* target installed by the upstream project. This enables
downstream targets to acquire the usage requirements of its dependencies by
linking against upstream INTERFACEs.

This design leads to alot of targets being created. In order to minimize
target name conflicts and to provide organization to extensions, each
target is exported with a namespace prefix. There is one namespace
per prefix: vmm, test, and userspace. When each target is exported,
CMake prepends each target name with `${PREFIX}::`.

## Extensions

A Bareflank "extension" is an external CMake project (i.e., one defined in a
separate git repo) that depends on a target defined in this repo. To build
an extension, you first tell the superbuild where it is. This
is done by passing `-DEXTENSION="path/to/extension"` to cmake. From there,
the superbuild will *include* the extension's root CMakeLists.txt
into its own CMakeLists.txt (see `include_external_extensions` for details).
The include part is crucial because it means the extension's CMakeLists.txt
is included C-header-file style into the superbuild. This means that all of
the configuration state and [helper macros](../scripts/cmake/macros.cmake)
are accessible from the extension's cmake files.

After inclusion, the extension's cmake files are processed just like the ones
defined in this repo. Extension writers must specify the dependencies their
extension has, both at the superbuild level and the target level. There is
a helper macro to make specifying superbuild level dependencies easier:

`add_subproject`
  - Adds a project to the superbuild. Passing `DEPENDS <superbuild-dep>`
    to this macro informs the superbuild that `<superbuild-dep>`
    must be built before this project. Note that this macro is passed a
    prefix string ('vmm', 'test', or 'userspace') that specifies what
    toolchain to use. This string becomes the namespace for each of the
    targets defined by the project.

Dependencies between targets defined *in the same project* are specified like
normal with the standard CMake commands such as `target_link_libraries`.
To link against a target defined in a separate project, use the standard
commands as normal, but remember that every external target is prefixed
with a namespace, so in general the link command will look like

`target_link_libraries(foo_vmm PUBLIC ${PREFIX}::bfvmm)`

Of course if the prefix string is known for certain, you can use it directly.
This will be the common case for most extension writers; the 'vmm'
prefix is the only one being used, so the the link command would be

`target_link_libraries(foo_vmm PUBLIC vmm::bfvmm)`

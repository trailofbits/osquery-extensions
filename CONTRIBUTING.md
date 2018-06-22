Contributing to the osquery-extensions repository
======

## What should I know before I get started?

The kinds of osquery features should be in an extension:
* ...
* ...
* ...

Examples of new extensions we would accept:
* ...
* ...
* ...

All code changes and additions, even if written by developers at Trail of Bits, must be reviewed using a GitHub pull request.

### Contributor License Agreement ("CLA")

In order to accept your pull request, we need you to submit a CLA. You only need to do this once to work on any of Trail of Bits' open source projects.

Complete your CLA here: TBD

By contributing to osquery-extensions, you agree that your contributions will be licensed under both the `LICENSE` file and the `COPYING` file in the root directory of this source tree.

## References on developing osquery extensions

* [Main documentation on osquery SDK](https://osquery.readthedocs.io/en/stable/development/osquery-sdk/)
* [C++ example of an osquery extension](https://github.com/facebook/osquery/tree/master/osquery/examples)
* [Developing osquery extensions in Python]()
* [Developing osquery extensions in Go]()

## Creating good pull requests

* Fill in the [required template](https://github.com/trailofbits/osquery-extensions/blob/master/PULL_REQUEST_TEMPLATE.md)
* Platform-dependent code is okay where it makes sense, but multi-platform support is always a plus
* Do not include issue numbers in the PR title
* See the [C++ code quality standards and expectations](#C++-style-guide), below

## Submitting issues (bugs or extension ideas)

Both bugs and enhancement suggestions are tracked as GitHub issues. Create an issue and provide the following information.

### For bugs
* **Describe the current behavior and explain which behavior you expected to see instead** and why.
* **Provide specific examples to demonstrate the steps.** Include copy/pasteable snippets which you use in those examples, as Markdown code blocks.
* **Specify which version of osquery** you're using.
* **Specify the name and version of the OS** you're using.

### For enhancements
* **Use a clear and descriptive title** for the issue to identify the suggestion.
* **Provide a step-by-step description of the suggested enhancement** in as many details as possible.
* **Include `osqueryi` output snippets or screenshots** which help demonstrate the steps or the extension to which the suggestion is related.
* **Explain why this enhancement would be useful to osquery users** and isn't something that can or should be implemented in osquery core.
* **List other applications that currently implement this feature**, if you know of any.

## C++ style guide

TBD

## Extension documentation guide

* Use [Markdown](https://guides.github.com/features/mastering-markdown/) to add a README.md for your extension, following the structure of the existing extensions.
* Add a row to the table in the top-level `README.md` in the extensions repo, that describes your extension.

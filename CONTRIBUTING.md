Contributing to the osquery-extensions repository
======

## What should I know before I get started?

The kinds of osquery features should be in an extension:
* virtual tables that could read potentially sensitive user data
* any capability to change the state of the system
* any virtual table that, by executing, needs to generate network traffic to third parties
* any capability that might increase the osquery binary significantly relative to its default size
* any virtual table that, although useful, could easily impact system performance

Hypothetical examples of new extensions we might expect to receive in community contributions:
* a virtual table that actively enumerates the nearby network nodes, nmap style
* a virtual table that adds threat intelligence from third-party services to an existing table's results
* a virtual table that returns all DNS queries made by the endpoint (an example of something potentially sensitive)

## Get in Touch

Let's discuss your idea before you start. We do our best to respond in the [osquery Slack instance](https://osquery.slack.com). Stop into `#extensions` and say hello.

## Contributor License Agreement ("CLA")

In order to accept your pull request, we need you to submit a CLA. You only need to do this once to work on any of Trail of Bits' open source projects. You will be prompted to complete the CLA upon your first pull request.

By contributing to osquery-extensions, you agree that your contributions will be licensed under both the `LICENSE` file and the `COPYING` file in the root directory of this source tree.

## References on developing osquery extensions

* [Main documentation on osquery SDK](https://osquery.readthedocs.io/en/stable/development/osquery-sdk/)
* [C++ example of an osquery extension](https://github.com/facebook/osquery/tree/master/osquery/examples)
* [Developing osquery extensions in Python](https://github.com/osquery/osquery-python)
* [Developing osquery extensions in Go](https://github.com/kolide/osquery-go)
* [Nick Anderson's walkthrough of developing an osquery extension on Windows](https://brewfault.io/blog/2018/1/29/building-extensions-for-osquery-on-windows)

## Git workflow

Please do all of your development in a feature branch, on your own fork of osquery-extensions. You should clone osquery-extensions normally, like this:

```
git clone git@github.com:trailofbits/osquery-extensions.git
```

Then, your "remote" should be set up as follows:

```
$ cd osquery-extensions
$ git remote -v
origin  git@github.com:trailofbits/osquery-extensions.git (fetch)
origin  git@gitHub.com:trailofbits/osquery-extensions.git (push)
```

Now, use the GitHub UI to fork osquery-extensions to your personal GitHub organization. Then, add the remote URL of your fork to git's local remotes:

```
$ git remote add $USER git@github.com:$USER/osquery-extensions.git
```

Now, your "remote" should be set up as follows:

```
$ git remote -v
yourname git@github.com:yourname/osquery-extensions.git (fetch)
yourname git@github.com:yourname/osquery-extensions.git (push)
origin  git@github.com:trailofbits/osquery-extensions.git (fetch)
origin  git@gitHub.com:trailofbits/osquery-extensions.git (push)
```

When you're ready to start working on a new feature, create a new branch:

```
$ git checkout -b my-feature
```

Write your code and when you're ready to put up a Pull Request, push your local branch to your fork:

```
$ git add .
$ git commit -m "my awesome feature!"
$ git push -u $USER my-feature
```

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

## Pull Request workflow

All code changes and additions, even if written by developers at Trail of Bits, must be reviewed using a GitHub pull request. Visit https://github.com/trailofbits/osquery-extensions and use the web UI to create a Pull Request. Once your pull request has gone through sufficient review and iteration, please squash all of your commits into one commit.

In most cases your PR should represent a single body of work. It is fine to change unrelated small things like nits or code-format issues but make every effort to submit isolated changes. This makes documentation, references, regression tracking and if needed, a revert, easier.

## Updating Pull Requests

Pull requests will often need revision, but don't be discouraged! That's normal.

Please feel free to add several commits to your Pull Request. When it comes time to merge into **master** all commits in a Pull Request will be squashed using GitHub's tooling into a single commit. The development team will usually choose to remove the commit body and keep the GitHub-appended `(#PR)` number in the commit title.

**You make updates to your pull request**

If the pull request needs changes, or you decide to update the content, consider 'amending' your previous commit:

```
$ git commit --amend
```

Like squashing, this changes the branch history so you'll need to force push the changes to update the pull request:

```
$ git push -f
```

In all cases, if the pull request is triggering automatic build/integration tests, the tests will rerun reflecting your changes.

### Linking issues

Once you submit your pull request, link the GitHub issue which your Pull Request implements. To do this, if the relevant issue is #7, then simply type "#7" somewhere in the Pull Request description or comments. This links the Pull Request with the issue, which makes things easier to track down later on.

### Creating good pull requests

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

Trail of Bits recommends the [Google style guide for C++](https://google.github.io/styleguide/cppguide.html).

## Extension documentation guide

* Use [Markdown](https://guides.github.com/features/mastering-markdown/) to add a README.md for your extension, following the structure of the existing extensions.
* Add a row to the table in the top-level `README.md` in the extensions repo, that describes your extension.
* Consider using spellcheck and a Markdown linter, because you'd be surprised what you miss.

# Contributing to Orion-Belt

First of all, thank you for considering contributing to **Orion-Belt** ❤️
Community involvement is what makes open-source projects thrive.

Orion-Belt is an infrastructure and security-focused project, so we value
**clarity, correctness, security, and thoughtful design** in all contributions.

---

## Ways to Contribute

There are many ways to contribute, including:

* Reporting bugs
* Suggesting features or improvements
* Improving documentation
* Adding tests
* Implementing new features
* Reviewing pull requests
* Building plugins or integrations

No contribution is too small.

---

## Reporting Bugs

If you find a bug, please open an issue and include:

* A clear and descriptive title
* Steps to reproduce the issue
* Expected behavior
* Actual behavior
* Environment details (OS, Go version, config, etc.)
* Relevant logs or error messages

If the issue is security-sensitive, **do not open a public issue**.
Please see the [Security](#security) section below.

---

## Feature Requests

Feature requests are welcome.

When proposing a feature, please include:

* The problem you are trying to solve
* Why existing functionality is insufficient
* A suggested approach or design (if possible)

Well-thought-out proposals have a much higher chance of being accepted.

---

## Development Setup

### Requirements

* Go (latest stable version recommended)
* PostgreSQL (or another supported database)
* Make
* SSH client (for testing)

### Clone the Repository

```bash
git clone https://github.com/zrougamed/orion-belt.git
cd orion-belt
```

### Build

```bash
make build
```

### Run Tests

```bash
make test
```

---

## Coding Guidelines

Please follow these guidelines to keep the codebase consistent and maintainable:

* Use `gofmt` and `go vet`
* Prefer clarity over cleverness
* Write small, focused commits
* Add tests for new functionality
* Avoid breaking public APIs without discussion
* Keep security implications in mind at all times

---

## Commit Messages

Use clear and descriptive commit messages.
A good format is:

```
component: short description

Optional longer explanation if needed
```

Example:

```
agent: add heartbeat retry mechanism
```

---

## Pull Request Process

1. Fork the repository
2. Create a feature or fix branch
3. Make your changes
4. Ensure tests pass
5. Open a pull request against `main`
6. Clearly describe **what** and **why**

Pull requests may be reviewed for:

* Code quality
* Security implications
* Architectural consistency
* Documentation impact

Please be patient — reviews may take time.

---

## Security

If you discover a security vulnerability, **do not disclose it publicly**.

Please report it privately by emailing:

**[med@zrouga.email](mailto:med@zrouga.email)**

Responsible disclosure is greatly appreciated.

---

## License

By contributing to Orion-Belt, you agree that your contributions will be licensed under the **Apache License 2.0**.

---

## Community & Participation

Orion-Belt is built **with the community, for the community**.

Whether you are:

* A security engineer
* A DevOps practitioner
* A Go developer
* Or simply curious about SSH internals and access control

**You are welcome here.**

Feel free to:

* Ask questions
* Share ideas
* Challenge assumptions
* Propose improvements

Let’s build a **secure, auditable, and open access platform** together

Thank you for being part of the Orion-Belt community.

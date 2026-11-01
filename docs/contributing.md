# 🤝 Contributing to `mifarepy`

Thank you for considering a contribution to **mifarepy**! We value all forms of contributions—bug reports, feature requests, documentation improvements, and code enhancements. To make collaboration smooth and efficient, please follow the guidelines below.

---

## 📋 Code of Conduct

Our community is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its principles and treat everyone with respect and courtesy.

---

## 🛠 Get Started

### 1. Report Issues

- Use **GitHub Issues** to report bugs or request features.
- When filing an issue:
  - Provide a clear title and description.
  - Include steps to reproduce, expected vs. actual behavior, and environment details.
  - Attach logs, screenshots, or minimal code snippets if helpful.

### 2. Fork & Clone

```bash
git clone https://github.com/SparkDrago05/mifarepy.git
cd mifarepy
git checkout -b feature/your-topic
```

- Use a descriptive branch name prefixed with `feature/`, `fix/`, or `docs/`.

### 3. Set Up Development Environment

```bash
python3 -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

- This installs **mifarepy** in editable mode with the test dependencies.

---

## 🚧 Writing Code

- Follow **PEP8** style; project uses **Pycharm** (auto-format) and **Flake8** (linting).
- Write clear, modular code with meaningful names and docstrings.
- Add or update **pytest** tests under `tests/` to cover new behavior.
- Ensure all tests pass:

  ```bash
  pytest --maxfail=1 --disable-warnings -q
  ```

- Maintain or improve code coverage, especially for critical paths.

---

## 💬 Commits & Pull Requests

### Commit Messages

- Follow **Conventional Commits**:
  - `feat: add new reader method`
  - `fix: correct CRC calculation`
  - `docs: update usage guide`
  - `chore: bump version to 1.2.0`

### Pull Request

- Push your branch and open a PR against the `main` branch.
- In the PR description:
  - Summarize the change, motivation, and any linking issue.
  - List manual testing steps, if applicable.
- Respond to review feedback and update your PR until approved.

---

## ✅ After Merge

- Celebrate! 🎉 Your contributions help improve **mifarepy** for everyone.
- Keep your fork and branches tidy by deleting merged branches.

---

## 📜 License

By contributing, you agree that your changes will be licensed under the project's [LGPL v3.0 or later](LICENSE).

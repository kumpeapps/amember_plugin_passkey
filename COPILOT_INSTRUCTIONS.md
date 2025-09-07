# GitHub Copilot Instructions for amember_plugin_passkey

## Purpose
This file provides guidelines for using GitHub Copilot to make updates to the amember_plugin_passkey project. Follow these instructions to ensure all changes are safe, production-ready, and maintainable.

## General Guidelines
- **No debug/test code:** Do not add or re-enable any debug, test, or demo files/statements in production code. All logging should be minimal and only for error handling.
- **Admin login:** Do not reintroduce passkey support for admin login unless explicitly requested and tested.
- **File cleanup:** Remove obsolete, unused, or test files after feature changes. Only keep files necessary for production.
- **Error handling:** Use proper error handling. Avoid exposing sensitive information in logs or error messages.
- **Documentation:** Update README.md and relevant documentation for any new features, changes, or API updates.
- **Composer:** Ensure all Composer dependencies are up-to-date and required for production. Do not add unnecessary packages.
- **Database:** Only modify database tables/columns if required for new features. Document all schema changes.
- **Code style:** Follow existing code style and structure. Use clear, descriptive comments for complex logic.
- **Testing:** If new features are added, provide clear instructions for manual testing. Do not add test files to the main repo.

## Copilot Usage
- Use Copilot to suggest code, but always review and validate before committing.
- Do not accept suggestions that violate the above guidelines.
- If unsure, ask for clarification or review with a human before merging.

## Release Checklist
- [ ] No debug/test/demo files or statements present
- [ ] All documentation updated
- [ ] Composer dependencies reviewed
- [ ] Database changes documented
- [ ] Code reviewed for style and security
- [ ] Manual test instructions provided

---
**Maintainers:** Update these instructions as the project evolves.

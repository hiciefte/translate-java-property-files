# Translate Java Property Files

This project automates the translation of Java `.properties` files into multiple languages using OpenAI's GPT-based
APIs. It detects changed `.properties` files via Git, queues them for translation, applies a glossary for consistent
terminology, and archives completed work.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Installation](#installation)
- [Usage](#usage)
- [Glossary](#glossary)
- [Testing](#testing)
- [Additional Notes](#additional-notes)

---

## Prerequisites

1. **Python 3.9+**  
   This script should work in Python 3.7+, but 3.9 or higher is recommended.

2. **OpenAI API Key**  
   You need an OpenAI API key to use GPT-based translations. Sign up at [OpenAI](https://platform.openai.com/) to obtain
   a key.

3. **Git**  
   If you want to leverage Git-based detection of changed `.properties` files, ensure Git is installed and the target
   project is a Git repository.

---

## Project Structure

- **`src/translate_localization_files.py`**  
  Main script containing the logic for translating `.properties` files.

- **`config.yaml`**  
  Stores configurable parameters such as paths, OpenAI model name, etc.

- **`glossary.json`**  
  Contains a language-specific glossary to ensure consistent translations.

- **`tests/`**  
  Holds test files (e.g., integration tests).

- **`venv/`**  
  (Optional) A virtual environment for isolating Python dependencies.

---

## Configuration

1. **Create a `.env` File**  
   Place a `.env` file in the **root** directory with your OpenAI API key: `OPENAI_API_KEY=your_secret_api_key_here`
2. **Set up `config.yaml`**

- **`target_project_root`**: Absolute path to the Git repository root.
- **`input_folder`**: Path to the folder containing `.properties` files to be translated.
- **`glossary_file_path`**: Path to `glossary.json`.
- **`model_name`**: Name of the OpenAI model (e.g., `gpt-4`, `gpt-3.5-turbo`).
- **`translation_queue_folder`** & **`translated_queue_folder`**: Folders to manage the translation workflow.
- **`dry_run`**: If `true`, the script will simulate file operations without actually copying or moving files.

**Example** `config.yaml`:

```yaml
target_project_root: "/path/to/your/git/repo"
input_folder: "/path/to/properties/files"
glossary_file_path: "glossary.json"
model_name: "gpt-4"
translation_queue_folder: "translation_queue"
translated_queue_folder: "translated_queue"
dry_run: false
```

## Installation

1. **Clone This Repository** (if you haven't already):
   ```bash
   git clone https://github.com/YourUsername/YourRepo.git
   cd YourRepo
   ```

2. **Create & Activate a Virtual Environment** (recommended):
   ```bash
   # For Linux/Mac
   python3 -m venv venv
   source venv/bin/activate

   # For Windows
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set Up `.env` File**  
   Make sure the `.env` file at the repository root contains:
   ```
   OPENAI_API_KEY=your_secret_api_key_here
   ```

---

## Usage

From within the `src` folder, run:

```bash
python translate_localization_files.py
```

### What the Script Does

1. **Validates Paths**  
   Ensures paths in `config.yaml` exist and are accessible.

2. **Checks Git for Changes**  
   Uses `git status` to detect recently modified `.properties` files in the `input_folder`.

3. **Copies Changed Files to a Queue**  
   Copies changed files to `translation_queue_folder`.

4. **Translates Files**  
   The script scans each file for lines needing translation (based on a comparison to the source). It then calls the
   OpenAI API, respecting placeholders, glossaries, and existing translations.

5. **Copies Translated Files Back**  
   Finished translations are moved to `translated_queue_folder` and then synced back to `input_folder`.

6. **Archiving**  
   Archives the original files from the queue folder to an `archive` subfolder for record-keeping.

7. **Cleanup**  
   If `dry_run` is set to `false`, the queue folders are cleared after successful processing.

#### Dry Run Mode

If `dry_run` is `true` in `config.yaml`, the script will **not** move or copy any files. Instead, it will log all
intended operations, allowing you to safely test.

---

## Glossary

- **`glossary.json`** ensures certain terms are translated consistently or left untranslated.
    - Key: Language code (e.g., `"de"`, `"cs"`).
    - Value: Another dictionary of `{ "Term": "Translation" }`.

Example snippet:

```json
{
  "de": {
    "Bitcoin": "Bitcoin",
    "Bisq": "Bisq"
  },
  "cs": {
    "Bitcoin": "Bitcoin"
  }
}
```

---

## Testing

1. **Install `pytest`** (already in `requirements.txt`):
   ```bash
   pip install pytest
   ```
2. **Run Tests**:
   ```bash
   pytest -v
   ```
   Tests reside in the `tests` folder. Logs may appear in `tests/translation_log.log`.

---

## Additional Notes

- **Token Limits**  
  The script attempts to keep prompts within token limits defined in `translate_localization_files.py` (
  `MAX_MODEL_TOKENS`). Adjust as necessary for your model.

- **Error Handling & Retries**  
  The script includes retry logic with exponential backoff if the OpenAI API returns errors or rate-limit responses.

- **Logging**  
  Progress, errors, and debug messages go to `translation_log.log` (in both the `src` and `tests` folders, depending on
  the run context).

---

If you encounter any issues or need additional help, feel free to open an issue or contact the maintainers!

   
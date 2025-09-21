"""Unit tests for the app_config module."""
import os
from unittest.mock import patch, mock_open, MagicMock

import pytest
import yaml

from src.app_config import AppConfig, load_app_config


class TestAppConfig:
    """Test cases for the AppConfig dataclass."""

    def test_app_config_creation(self):
        """Test that AppConfig can be created with required fields."""
        config = AppConfig(
            project_root="/test/root",
            target_project_root="/test/target",
            input_folder="/test/input",
            glossary_file_path="/test/glossary.json",
            model_name="gpt-4",
            review_model_name="gpt-4o",
            max_model_tokens=4000,
            dry_run=False,
            holistic_review_chunk_size=75,
            max_concurrent_api_calls=1,
            language_codes={"de": "German"},
            name_to_code={"german": "de"},
            style_rules={},
            precomputed_style_rules_text={},
            brand_glossary=["Bisq"],
            translation_queue_folder="/tmp/queue",
            translated_queue_folder="/tmp/translated",
            preserve_queues_for_debug=False,
            openai_client=None
        )

        assert config.project_root == "/test/root"
        assert config.model_name == "gpt-4"
        assert config.dry_run is False
        assert config.language_codes == {"de": "German"}


class TestLoadAppConfig:
    """Test cases for the load_app_config function."""

    def test_load_config_with_valid_yaml_file(self):
        """Test loading configuration from a valid YAML file."""
        mock_config = {
            "target_project_root": "/custom/target",
            "input_folder": "/custom/input",
            "model_name": "gpt-4o-mini",
            "dry_run": True,
            "supported_locales": [
                {"code": "de", "name": "German"},
                {"code": "es", "name": "Spanish"}
            ],
            "logging": {
                "log_level": "DEBUG",
                "log_file_path": "test.log"
            }
        }

        with patch("builtins.open", mock_open(read_data=yaml.dump(mock_config))):
            with patch("os.path.exists", return_value=True):
                with patch("os.access", return_value=True):
                    with patch("src.logging_config.setup_logger") as mock_logger:
                        mock_logger.return_value = MagicMock()
                        with patch.dict(os.environ, {}, clear=True):
                            config = load_app_config()

        assert config.target_project_root == "/custom/target"
        assert config.input_folder == "/custom/input"
        assert config.model_name == "gpt-4o-mini"
        assert config.dry_run is True
        assert config.language_codes == {"de": "German", "es": "Spanish"}
        assert config.name_to_code == {"german": "de", "spanish": "es"}

    def test_load_config_with_missing_file_uses_defaults(self):
        """Test that missing config file results in default values."""
        # Mock config.get calls to return default values, with dry_run=True to avoid API key requirement
        mock_config = {"dry_run": True}

        with patch("src.app_config._load_yaml_config", return_value=mock_config):
            with patch("os.path.exists", return_value=False):
                with patch("src.logging_config.setup_logger") as mock_logger:
                    mock_logger.return_value = MagicMock()
                    with patch.dict(os.environ, {}, clear=True):
                        config = load_app_config()

        # Should use default values
        assert config.model_name == "gpt-4"
        assert config.dry_run is True
        assert config.holistic_review_chunk_size == 75
        assert config.max_concurrent_api_calls == 1

    def test_load_config_with_environment_overrides(self):
        """Test that environment variables override config file values."""
        mock_config = {"model_name": "gpt-4", "dry_run": True}

        with patch("builtins.open", mock_open(read_data=yaml.dump(mock_config))):
            with patch("os.path.exists", return_value=True):
                with patch("os.access", return_value=True):
                    with patch("src.logging_config.setup_logger") as mock_logger:
                        mock_logger.return_value = MagicMock()
                        with patch.dict(os.environ, {
                            "REVIEW_MODEL_NAME": "gpt-4o",
                            "HOLISTIC_REVIEW_CHUNK_SIZE": "100"
                        }):
                            config = load_app_config()

        assert config.model_name == "gpt-4"  # From config file
        assert config.review_model_name == "gpt-4o"  # From environment
        assert config.holistic_review_chunk_size == 100  # From environment

    def test_load_config_with_dotenv_file(self):
        """Test that .env file is loaded properly."""
        mock_config = {"model_name": "gpt-4", "dry_run": True}

        with patch("builtins.open", mock_open(read_data=yaml.dump(mock_config))):
            with patch("os.path.exists") as mock_exists:
                # Mock .env file exists in project root
                mock_exists.side_effect = lambda path: path.endswith("/.env") or path.endswith("config.yaml")
                with patch("os.access", return_value=True):
                    with patch("src.app_config.load_dotenv") as mock_load_dotenv:
                        with patch("src.logging_config.setup_logger") as mock_logger:
                            mock_logger.return_value = MagicMock()
                            with patch.dict(os.environ, {}, clear=True):
                                load_app_config()

                # Should have called load_dotenv
                mock_load_dotenv.assert_called_once()

    def test_openai_client_creation_with_api_key(self):
        """Test that OpenAI client is created when API key is present."""
        mock_config = {"dry_run": False}

        with patch("builtins.open", mock_open(read_data=yaml.dump(mock_config))):
            with patch("os.path.exists", return_value=True):
                with patch("os.access", return_value=True):
                    with patch("src.logging_config.setup_logger") as mock_logger:
                        mock_logger.return_value = MagicMock()
                        with patch("src.app_config.AsyncOpenAI") as mock_openai:
                            mock_client = MagicMock()
                            mock_openai.return_value = mock_client
                            with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test-key"}):
                                config = load_app_config()

        mock_openai.assert_called_once_with(api_key="sk-test-key")
        assert config.openai_client == mock_client

    def test_openai_client_none_in_dry_run(self):
        """Test that OpenAI client is None in dry run mode."""
        mock_config = {"dry_run": True}

        with patch("builtins.open", mock_open(read_data=yaml.dump(mock_config))):
            with patch("os.path.exists", return_value=True):
                with patch("os.access", return_value=True):
                    with patch("src.logging_config.setup_logger") as mock_logger:
                        mock_logger.return_value = MagicMock()
                        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
                            config = load_app_config()

        assert config.openai_client is None

    def test_missing_openai_key_exits_in_production_mode(self):
        """Test that missing OpenAI API key causes system exit in production mode."""
        mock_config = {"dry_run": False}

        with patch("builtins.open", mock_open(read_data=yaml.dump(mock_config))):
            with patch("os.path.exists", return_value=True):
                with patch("src.logging_config.setup_logger") as mock_logger:
                    mock_logger.return_value = MagicMock()
                    with patch.dict(os.environ, {}, clear=True):
                        with pytest.raises(SystemExit):
                            load_app_config()

    def test_style_rules_preprocessing(self):
        """Test that style rules are properly preprocessed."""
        mock_config = {
            "dry_run": True,  # Add dry_run to avoid OpenAI key requirement
            "supported_locales": [
                {"code": "de", "name": "German"}
            ],
            "style_rules": {
                "de": ["Rule 1", "Rule 2"]
            }
        }

        with patch("builtins.open", mock_open(read_data=yaml.dump(mock_config))):
            with patch("os.path.exists", return_value=True):
                with patch("os.access", return_value=True):
                    with patch("src.logging_config.setup_logger") as mock_logger:
                        mock_logger.return_value = MagicMock()
                        with patch.dict(os.environ, {}, clear=True):
                            config = load_app_config()

        assert "de" in config.precomputed_style_rules_text
        assert "German" in config.precomputed_style_rules_text["de"]
        assert "Rule 1" in config.precomputed_style_rules_text["de"]
        assert "Rule 2" in config.precomputed_style_rules_text["de"]

    def test_custom_config_file_path(self):
        """Test using custom config file path via environment variable."""
        mock_config = {"model_name": "custom-model", "dry_run": True}

        with patch("builtins.open", mock_open(read_data=yaml.dump(mock_config))):
            with patch("os.path.exists", return_value=True):
                with patch("os.access", return_value=True):
                    with patch("src.logging_config.setup_logger") as mock_logger:
                        mock_logger.return_value = MagicMock()
                        with patch.dict(os.environ, {"TRANSLATOR_CONFIG_FILE": "/custom/config.yaml"}):
                            config = load_app_config()

        assert config.model_name == "custom-model"
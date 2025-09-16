import logging
import sys
import os
from logging import Handler

# Import tqdm here, as it's now a dependency for our custom handler.
from tqdm import tqdm


class TqdmLoggingHandler(Handler):
    """
    Custom logging handler that uses tqdm.write to output log messages.
    This prevents log messages from interfering with the tqdm progress bar.
    """
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)

    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg, file=sys.stderr)  # Write to stderr to match tqdm's default
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handleError(record)


def setup_logger(log_level_str: str, log_file_path: str, log_to_console: bool) -> logging.Logger:
    """
    Set up the logger for the translation script.

    Configures a logger with a file handler and a custom tqdm-aware stream handler.
    This ensures that log messages do not interfere with the tqdm progress bars
    while providing both file and console logging.

    Args:
        log_level_str: The logging level as a string (e.g., 'INFO', 'DEBUG').
        log_file_path: The path to the log file.
        log_to_console: A boolean indicating whether to log to the console.

    Returns:
        The configured logger instance.
    """
    # Use a specific logger name to avoid interfering with other loggers.
    logger = logging.getLogger("translation_script")

    # Set the logging level from the config string
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    logger.setLevel(log_level)

    # Clear any existing handlers to prevent duplicate logging
    if logger.hasHandlers():
        logger.handlers.clear()

    # Prevent the log messages from being passed to the root logger
    logger.propagate = False

    # Define a standard formatter for log messages
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # --- File Handler ---
    # Create the log directory if it doesn't exist
    log_dir = os.path.dirname(log_file_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    # Add a handler to write log messages to a file
    file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    # --- End File Handler ---

    # --- Console Handler ---
    # Use our custom TqdmLoggingHandler for console output
    if log_to_console:
        # We now use the custom handler that plays nice with tqdm.
        tqdm_handler = TqdmLoggingHandler()
        tqdm_handler.setFormatter(formatter)
        logger.addHandler(tqdm_handler)
    # --- End Console Handler ---

    return logger

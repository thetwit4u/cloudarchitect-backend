"""
Logging configuration for the application.
"""
import logging.config

def setup_logging():
    """Configure logging for the application."""
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "detailed": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "detailed",
                "level": "DEBUG",
            },
            "file": {
                "class": "logging.FileHandler",
                "filename": "app.log",
                "formatter": "detailed",
                "level": "DEBUG",
            },
        },
        "loggers": {
            "app": {
                "handlers": ["console", "file"],
                "level": "DEBUG",
                "propagate": False,
            },
            "app.routers": {
                "handlers": ["console", "file"],
                "level": "DEBUG",
                "propagate": False,
            },
            "app.services": {
                "handlers": ["console", "file"],
                "level": "DEBUG",
                "propagate": False,
            },
        },
        "root": {
            "handlers": ["console"],
            "level": "INFO",
        },
    }
    logging.config.dictConfig(logging_config)

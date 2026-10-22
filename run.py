"""Start the QSBAC Flask web application."""

from app import create_app

app = create_app()

# Increase allowed request size for biometric image uploads
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["MAX_FORM_MEMORY_SIZE"] = 50 * 1024 * 1024
app.config["MAX_FORM_PARTS"] = 100


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
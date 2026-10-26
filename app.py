from flask import Flask, render_template
from config import JWT_SECRET

app = Flask(__name__)
app.config["JWT_SECRET"] = JWT_SECRET


@app.get("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

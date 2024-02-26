from Website import create_app

app = create_app()

# Main app function.
if __name__ == '__main__':
    app.run(debug=True)

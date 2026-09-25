import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def check_website(url):

    result = {
        "url": url,
        "status_code": None,
        "server": None,
        "headers": {}
    }

    try:

        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True
        )

        result["status_code"] = response.status_code
        result["server"] = response.headers.get("Server")

        for header in SECURITY_HEADERS:

            result["headers"][header] = (
                header in response.headers
            )

    except requests.RequestException as error:

        result["error"] = str(error)

    return result
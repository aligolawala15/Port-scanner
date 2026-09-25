import socket
import ssl


def check_tls(host, port=443):

    result = {}

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (host, port),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

                result["tls_version"] = (
                    secure_socket.version()
                )

                result["cipher"] = (
                    secure_socket.cipher()
                )

                result["certificate_subject"] = (
                    certificate.get("subject")
                )

                result["certificate_issuer"] = (
                    certificate.get("issuer")
                )

    except Exception as error:

        result["error"] = str(error)

    return result	
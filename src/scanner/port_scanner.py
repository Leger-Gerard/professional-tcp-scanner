import socket
import time


def scan_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """
    Retourne True si le port TCP est ouvert.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        return result == 0


def main() -> None:
    print("=" * 50)
    print("      Scanner de ports TCP - GLG-TECH")
    print("=" * 50)

    host = input("Adresse IP ou nom d'hôte : ").strip()
    start_port = int(input("Port de début : "))
    end_port = int(input("Port de fin : "))

    print(f"\nScan de {host} de {start_port} à {end_port}...\n")

    open_ports = []
    start_time = time.time()

    for port in range(start_port, end_port + 1):
        if scan_port(host, port):
            print(f"[OUVERT] Port {port}")
            open_ports.append(port)

    elapsed = time.time() - start_time

    print("\n" + "=" * 50)
    print("Résultats du scan")
    print("=" * 50)

    if open_ports:
        print("Ports ouverts :", ", ".join(map(str, open_ports)))
    else:
        print("Aucun port ouvert détecté.")

    print(f"Temps d'exécution : {elapsed:.2f} seconde(s)")
"""Order export service for the snapshot fixture. Insecure on purpose."""

import subprocess

DB_PASSWORD = "hunter2-not-a-real-secret"


def export_orders(customer_id):
    return subprocess.run(f"pg_dump orders --where id={customer_id}", shell=True)

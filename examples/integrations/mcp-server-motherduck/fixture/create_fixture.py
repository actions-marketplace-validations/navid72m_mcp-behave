#!/usr/bin/env python3
"""Create disposable synthetic DuckDB fixture using the target's pinned duckdb."""
import sys
from pathlib import Path
import duckdb

out = Path(sys.argv[1] if len(sys.argv) > 1 else "sample.duckdb")
if out.exists():
    out.unlink()

con = duckdb.connect(str(out))
con.execute("""
    CREATE TABLE items (id INTEGER PRIMARY KEY, name VARCHAR, category VARCHAR, price DECIMAL(10, 2));
    INSERT INTO items VALUES
        (1, 'Alpha Sensor', 'hardware', 49.99),
        (2, 'Beta Module', 'hardware', 89.50),
        (3, 'Gamma License', 'software', 199.00);
    CREATE TABLE events (event_id INTEGER PRIMARY KEY, item_id INTEGER, quantity INTEGER, event_date DATE);
    INSERT INTO events VALUES
        (101, 1, 5, DATE '2026-01-15'),
        (102, 2, 2, DATE '2026-01-16'),
        (103, 3, 1, DATE '2026-01-17');
    CREATE VIEW item_revenue AS
    SELECT i.name, SUM(e.quantity * i.price) AS revenue
    FROM items i JOIN events e ON i.id = e.item_id
    GROUP BY i.name;
""")
con.close()
print(f"Created {out} (duckdb {duckdb.__version__})")

import sqlite3

import click
from flask import g, current_app
from flask.cli import with_appcontext


def get_db():
    if 'store' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_COLNAMES
        )
        g.db.row_factory = sqlite3.Row

    return g.db


def update_db(query, args=()):
    with get_db() as con:
        con.cursor().execute(query, args)
        status = con.commit()
        return status


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def close_db(e=None):
    db = g.pop('store', None)

    if db is not None:
        db.close()

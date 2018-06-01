from flask import Flask, request
from neo4j.v1 import GraphDatabase
import r2pipe
import tempfile
import json
import jsonpickle
import hashlib
import os
import string
import re
import subprocess
import base64
import difflib
import ast
import threading
import queue
import os
import argparse
import sys

CONFIG = {}
relationship_types = {}
relationship_types["functions"] = "CALLS"
relationship_types["imports"] = "IMPORTS"
relationship_types["strings"] = "HAS"
relationship_types["exports"] = "EXPORTS"
relationship_types["IOC"] = "TBD"


def setup(config_path):
    if os.path.exists(config_path):
        config_raw = ""

        with open(config_path) as file:
            for line in file.readlines():
                config_raw += line
        file.close

        config = json.loads(config_raw)
        return config


argp = argparse.ArgumentParser(description='Mal6raph API')
argp.add_argument('-c', '--config', required=True,
                  help='Path to the JSON config file for Mal6raph')
args = argp.parse_args()
CONFIG = setup(args.config)
app = Flask(__name__, static_url_path=CONFIG['STATIC_PATH'])
thread_lock = threading.Lock()


class Neo4jDriver(object):
    def __init__(self):
        self._driver = GraphDatabase.driver(
            CONFIG['NEO4JURI'], auth=(CONFIG['USER'], CONFIG['PASSWORD']))

    def close(self):
        self._driver.close()

    def send_query(self, query):
        with self._driver.session() as session:
            with session.begin_transaction() as tx:
                result = tx.run(query)
        return result.records()

    def create_query_new_node(self, sample):
        query = "CREATE (sample_{0}:Sample) \n".format(sample.sha256)

        query += "SET sample_{0}.md5 = '{1}'\n".format(
            sample.sha256, sample.md5)
        query += "SET sample_{0}.sha256 = '{0}'\n".format(sample.sha256)
        query += "SET sample_{0}.strings = '{1}'\n".format(
            sample.sha256, json.dumps(sample.strings))
        query += "SET sample_{0}.imports = '{1}'\n".format(
            sample.sha256, json.dumps(sample.imports))
        query += "SET sample_{0}.exports = '{1}'\n".format(
            sample.sha256, json.dumps(sample.exports))
        query += "SET sample_{0}.arch = '{1}'\n".format(
            sample.sha256, sample.arch)
        query += "SET sample_{0}.bits = {1}\n".format(
            sample.sha256, sample.bits)
        query += "RETURN sample_{0}.id\n".format(sample.sha256)

        return query

    def create_query_functions(self, sample):
        if sample.functions != []:
            query = "MATCH (sample_{0}:Sample {{sha256:'{0}'}})\n".format(
                sample.sha256)
            for function in sample.functions:
                query += "CREATE (function_{0}:Function) \n".format(function.sha256)
                query += "SET function_{0}.md5 ='{1}'\n".format(
                    function.sha256, function.md5)
                query += "SET function_{0}.sha256 = '{0}'\n".format(
                    function.sha256)
                query += "SET function_{0}.size = {1}\n".format(
                    function.sha256, function.size)
                query += "SET function_{0}.arch = '{1}'\n".format(
                    function.sha256, function.arch)
                query += "SET function_{0}.bits = '{1}'\n".format(
                    function.sha256, function.bits)
                query += "SET function_{0}.call_refs = '{1}'\n".format(
                    function.sha256, json.dumps(function.call_refs))
                query += "SET function_{0}.ops = '{1}'\n".format(
                    function.sha256, json.dumps(function.ops))
                query += "SET function_{0}.offset = '{1}'\n".format(
                    function.sha256, json.dumps(function.offset))
                query += "CREATE (sample_{0})-[:CALLS]->(function_{1})\n".format(
                    sample.sha256, function.sha256)

        else:
            query = ""

        return query

    def create_query_get_functions(self, sample_sha256):
        query = "MATCH (f)<-[:CALLS]-(s:Sample {{sha256:'{0}'}}) ".format(
            sample_sha256)
        query += "RETURN f"
        return query

    def create_query_strings(self, sample):
        query = "MATCH (sample_{0}:Sample {{sha256:'{0}'}})\n".format(
            sample.sha256)
        for string in sample.strings['strings']:
            string_sanit = string.replace('=', '_').replace(
                '+', '__').replace('/', '___')

            query += "CREATE (string_{0}:String) \n".format(string_sanit)
            query += "SET string_{0}.string = '{1}'\n".format(
                string_sanit, string)
            # query += "SET string_{0}.size = {1}\n".format(
            #    string_sanit, string['size'])
            query += "CREATE (sample_{0})-[:HAS]->(string_{1})\n".format(
                sample.sha256, string_sanit)
        return query

    def create_query_imports(self, sample):
        query = query = "MATCH (sample_{0}:Sample {{sha256:'{0}'}})\n".format(
            sample.sha256)
        for imported in sample.imports:
            imported = imported['name']
            imported_sanit = imported.replace(
                '.', '_').replace('?', '_').replace('@', '_')

            query += "CREATE (import_{0}:Import) \n".format(imported_sanit)
            query += "SET import_{0}.name = '{1}'\n".format(
                imported_sanit, imported)
            query += "CREATE (sample_{0})-[:IMPORTS]->(import_{1})\n".format(
                sample.sha256, imported_sanit)
        return query

    def create_query_get_fct_same_size(self, fct_size):
        query = "MATCH (f:Function) WHERE f.size <= {0} AND f.size >= {1}".format(int(
            fct_size * (1+CONFIG['DIFF_SIZE_FCT'])), int(fct_size * (1-CONFIG['DIFF_SIZE_FCT'])))
        query += " RETURN f"
        return query

    def create_query_function_similar(self, function_sha256,
                                      function_sha256_target,
                                      similarity):
        """
        query = "CREATE (function_" + function_sha256 + ")"
        query += "-[:SIMILAR {similarity: " + str(similarity) + "}]->"
        query += "(function_" + function_sha256_target + ")\n"
        """
        query = "MATCH (function_{0}:Function {{sha256:'{0}'}}), (function_{1}:Function {{sha256:'{1}'}})\n".format(
            function_sha256, function_sha256_target)
        query += "CREATE (function_{0})-[:SIMILAR_TO {similarity: {1}}]->(function_{2}\n".format(
            function_sha256, similarity, function_sha256_target)

        return query

    def create_query_sample_calls_function(self, sample_sha256,
                                           function_sha256):
        query = "MATCH (sample_{0}:Sample {{sha256:'{0}'}}), (function_{1}:Function {{sha256:'{1}'}})\n".format(
            sample_sha256, function_sha256)
        query += "CREATE (sample_{0})-[:CALLS]->(function_{1})\n".format(
            sample_sha256, function_sha256)
        return query

    def create_query_functions_relationship(self, function, sample_sha256):
        query = ""
        query_function_same_size = self.create_query_get_fct_same_size(
            function['size'])
        functions_same_size = self.send_query(query_function_same_size)
        similarities = {}
        fct_simil_id = {}
        threads = []
        queue_fct_same_size = queue.Queue(maxsize=0)

        for fct_same_size in functions_same_size:
            queue_fct_same_size.put(fct_same_size['f'])

        for i in range(CONFIG['NUMBER_THREADS']):
            thread = threading.Thread(target=calculate_simil_functions, args=(
                queue_fct_same_size, function, similarities, fct_simil_id))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        fct_max_simil = get_max_similarity(similarities)
        if fct_max_simil is not None:
            if similarities[fct_max_simil] == 1 and fct_max_simil == function['sha256']:
                #id_fct = fct_simil_id.get(fct_max_simil)
                query += self.create_query_sample_calls_function(
                    sample_sha256, function['sha256'])
            elif similarities[fct_max_simil] >= CONFIG['THRESHOLD_SIMILARITY']:
                query += self.create_query_function_similar(
                    function['sha256'], fct_max_simil, similarities[fct_max_simil])
        return query

    def create_query_sample_exists(self, sample_sha256):
        query = "MATCH (sample_{0}:Sample {{sha256 :'{0}'}})\n".format(
            sample_sha256)
        query += "RETURN sample_{0}\n".format(sample_sha256)
        return query


class Sample:
    def __init__(self, md5="", sha256="", functions=[], strings={}, imports=[],
                 exports=[], arch="", bits=0, s_id=0):
        self.md5 = md5
        self.sha256 = sha256
        self.functions = functions
        self.strings = strings
        self.imports = imports
        self.exports = exports
        self.arch = arch
        self.bits = bits
        self.id = s_id
        return


class Function:
    def __init__(self, md5="", sha256="", size=0, arch="",
                 bits=0, call_refs=[], ops=[], offset=""):
        self.md5 = md5
        self.sha256 = sha256
        self.size = size
        self.arch = arch
        self.bits = bits
        self.call_refs = call_refs
        self.ops = ops
        self.offset = offset
        return


# From http://hetland.org/coding/python/levenshtein.py
def levenshtein(a, b):
    "Calculates the Levenshtein distance between a and b."
    n, m = len(a), len(b)
    if n > m:
        # Make sure n <= m, to use O(min(n,m)) space
        a, b = b, a
        n, m = m, n
    current = range(n+1)
    for i in range(1, m+1):
        previous, current = current, [i]+[0]*n
        for j in range(1, n+1):
            add, delete = previous[j]+1, current[j-1]+1
            change = previous[j-1]
            if a[j-1] != b[i-1]:
                change = change + 1
            current[j] = min(add, delete, change)
    return current[n]


def create_function_from_analysis(binary_path, sample, functions, functions_sha256, queue_offsets):
    r2p = r2pipe.open(binary_path)
    while queue_offsets.empty() is False:
        offset = queue_offsets.get()
        r2p.cmd('af @ ' + offset)

        function_info = r2p.cmdj('afij @ ' + offset)[0]
        if function_info['size'] >= CONFIG['THRESHOLD_FCT_SIZE']:
            function_md5 = r2p.cmd(
                'ph md5 ' + str(function_info['size']) + ' @ ' + offset)
            function_sha256 = r2p.cmd(
                'ph sha256 ' + str(function_info['size']) + ' @ ' + offset)

            if function_sha256 not in functions_sha256:
                function = Function(
                    function_md5,
                    function_sha256,
                    function_info['size'],
                    sample.arch,
                    sample.bits,
                    function_info['callrefs'] if 'callrefs' in function_info else [
                    ])
                function.offset = str(offset)
                function_dec = r2p.cmdj('pdfj @ ' + offset)
                if function_dec is not None:
                    function.ops = [op['type']
                                    for op in function_dec['ops'] if op is not None]
                    functions.append(function)
                    functions_sha256.append(function_sha256)
                else:
                    pass

        queue_offsets.task_done()
    r2p.quit()


def perform_analysis(binary_path):
    sample = Sample()
    r2p = r2pipe.open(binary_path)
    r2p.cmd('aa')
    r2p.cmd('aac')

    info = r2p.cmdj('iaj')
    sample.arch = info['info']['arch']
    sample.bits = info['info']['bits']
    sample.imports = info['imports']
    sample.exports = info['exports']
    functions_info = r2p.cmdj('aflj')
    function_offsets = [str(func['offset'])
                        for func in functions_info if func['size'] >= CONFIG['THRESHOLD_FCT_SIZE']]
    strings_tmp = r2p.cmdj('izzj')
    sample.strings['strings'] = list(
        set([string['string']
             for string in strings_tmp['strings'] if string['size'] > CONFIG['THRESHOLD_STR_SIZE']]))
    functions = []
    functions_sha256 = []
    threads = []
    queue_offsets = queue.Queue(maxsize=0)

    for offset in function_offsets:
        queue_offsets.put(offset)

    for i in range(CONFIG['NUMBER_THREADS']):
        thread = threading.Thread(target=create_function_from_analysis, args=(
            binary_path, sample, functions, functions_sha256, queue_offsets))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    sample.functions = functions
    r2p.quit()
    return sample


def get_max_similarity(similarities_map):
    v = list(similarities_map.values())
    k = list(similarities_map.keys())
    try:
        return k[v.index(max(v))]
    except:
        return None

# From stackoverflow


def checksums(file_stream):
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    while True:
        data = file_stream.read(BUF_SIZE)
        if not data:
            break
        md5.update(data)
        sha256.update(data)
    return (md5, sha256)


def unique_list(l):
    ulist = []
    [ulist.append(x) for x in l if x not in ulist]
    return ulist


def calculate_simil_functions(queue_fct_same_size, function, similarities, fct_simil_id):
    while queue_fct_same_size.empty() is False:
        fct_same_size = queue_fct_same_size.get()

        if len(function['ops']) > len(ast.literal_eval(fct_same_size['ops'])):
            a, b = function['ops'], ast.literal_eval(fct_same_size['ops'])
        else:
            a, b = ast.literal_eval(fct_same_size['ops']), function['ops']

        leven = levenshtein(a, b)
        similarities[fct_same_size['sha256']] = 1 - (leven/len(a))


@app.route('/samples', methods=['POST'])
def post_sample():
    print(request.files)
    if 'file' not in request.files:
        return 'no file'

    file = request.files['file']
    if file.filename == '':
        return 'no file'

    db = Neo4jDriver()
    tmp_file = tempfile.NamedTemporaryFile()
    file.save(tmp_file.name)
    md5, sha256 = checksums(tmp_file)
    query_already_there = db.create_query_sample_exists(sha256.hexdigest())
    sample_exists = db.send_query(query_already_there)

    if len(list(sample_exists)) > 0:
        return "Sample already in the DB"

    else:
        sample = perform_analysis(tmp_file.name)

        if sample is not None:
            sample.md5 = md5.hexdigest()
            sample.sha256 = sha256.hexdigest()
            tmp_file.close()
            query_new_node = db.create_query_new_node(sample)
            if query_new_node != "":
                sample_id_result = db.send_query(query_new_node)
            for sample_id in sample_id_result:
                sample.id = sample_id['sample_{0}.id'.format(
                    sample.sha256)]
            query_new_strings = db.create_query_strings(sample)
            query_new_functions = db.create_query_functions(sample)
            query_new_imports = db.create_query_imports(sample)
            query = []

            if query_new_functions != "":
                query_new_functions = '\n'.join(
                    unique_list(query_new_functions.split('\n')))
                db.send_query(query_new_functions)
            if query_new_strings != "":
                db.send_query(query_new_strings)
            if query_new_imports != "":
                query_new_imports = '\n'.join(
                    unique_list(query_new_imports.split('\n')))
                db.send_query(query_new_imports)
            if query != []:
                for query in query:
                    if query != "":
                        db.send_query(query)

            db.close()
            return sample.md5 + " /// " + sample.sha256

        else:
            tmp_file.close()
            return "Error"


@app.route('/')
def serve_index():
    return app.send_static_file('index.html')


'''
GET sample + passes arguments in order to filter following some variables
Idea: defer the creation of the relationship between nodes when the user tries to access it => heavy lift will be done if it's necessary and for the realtionship wanted
'''


@app.route('/relation', methods=["GET"])
def get_sample():
    db = Neo4jDriver()
    sample_sha256 = request.args.get("sample", default="", type=str)
    similarity = request.args.get(
        "similarity", default=CONFIG['THRESHOLD_SIMILARITY'], type=int)  # OK for strings and functions
    relationship_type = request.args.get(
        "relationship", default="", type=str)

    if relationship_types.get(relationship_type) is None:
        return "Error"

    if relationship_type == "functions":
        query_get_functions_from_sample = db.create_query_get_functions(
            sample_sha256)
        functions_sample = db.send_query(query_get_functions_from_sample)
        query_relationship = []

        for item in functions_sample:
            function = item['f']
            query_fct_rel = db.create_query_functions_relationship(
                function, sample_sha256)
            if query_fct_rel != "":
                query_relationship.append(query_fct_rel)

        if query_relationship != []:
            for query in query_relationship:
                db.send_query(query)
        else:
            return "no relationship found"

    return "ok"


if __name__ == '__main__':
    app.run(port=CONFIG['PORT'], host=CONFIG['HOST'])

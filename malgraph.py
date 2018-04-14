from flask import Flask, request
from neo4j.v1 import GraphDatabase
import r2pipe
import tempfile
import json
import hashlib
import os
import string
import re
import subprocess

STATIC_PATH = '/static/'
FUNCTIONS_PATH = './functions/'
USER = 'neo4j'
PASSWORD = 'THIS_IS_ONLY_A_TEST'
THRESHOLD = 0.70
THRESHOLD_FCT_SIZE = 300
NEO4JURI = 'bolt://localhost:7687'
app = Flask(__name__, static_url_path=STATIC_PATH)


class Neo4jDriver(object):
    def __init__(self):
        self._driver = GraphDatabase.driver(NEO4JURI, auth=(USER, PASSWORD))

    def close(self):
        self._driver.close()

    def send_query(self, query):
        with self._driver.session() as session:
            with session.begin_transaction() as tx:
                result = tx.run(query)
        return result.records()

    def create_query_new_node(self, sample):
        query = "CREATE (sample_" + sample.sha256 + ":Sample) \n"
        query += "SET sample_" + sample.sha256 + ".md5 = '" + sample.md5 + "'\n"
        query += "SET sample_" + sample.sha256 + ".sha256 = '" + sample.sha256 + "'\n"
        query += "SET sample_" + sample.sha256 + ".strings = '" + \
            json.dumps(sample.strings) + "'\n"
        query += "SET sample_" + sample.sha256 + ".imports = '" + \
            json.dumps(sample.imports) + "'\n"
        query += "SET sample_" + sample.sha256 + ".exports = '" + \
            json.dumps(sample.exports) + "'\n"
        query += "SET sample_" + sample.sha256 + ".arch = '" + sample.arch + "'\n"
        query += "SET sample_" + sample.sha256 + \
            ".bits = " + str(sample.bits) + "\n"
        for function in sample.functions:
            query += "CREATE (function_" + function.sha256 + ":Function) \n"
            query += "SET function_" + function.sha256 + ".md5 = '" + \
                function.md5 + "'\n"
            query += "SET function_" + function.sha256 + ".sha256 = '" + \
                function.sha256 + "'\n"
            query += "SET function_" + function.sha256 + \
                ".size = " + str(function.size) + "\n"
            query += "SET function_" + function.sha256 + ".arch = '" + \
                function.arch + "'\n"
            query += "SET function_" + function.sha256 + ".bits = '" + \
                str(function.bits) + "'\n"
            query += "SET function_" + function.sha256 + ".call_refs = '" + \
                json.dumps(function.call_refs) + "'\n"
            query += "CREATE (sample_" + sample.sha256 + \
                ")-[:HAS]->(function_" + function.sha256 + ")\n"

        return query

    def create_query_get_fct_same_size(self, function):
        query = "MATCH (f:Function) WHERE f.size <= " + \
            str(int(function.size * 1.1))
        query += " AND f.size >= " + str(int(function.size * 0.9))
        query += " RETURN f.sha256"

        return query

    def create_query_function_similar(self, function_sha256,
                                      function_sha256_target,
                                      similarity):
        """
        query = "CREATE (function_" + function_sha256 + ")"
        query += "-[:SIMILAR {similarity: " + str(similarity) + "}]->"
        query += "(function_" + function_sha256_target + ")\n"
        """
        query = "MATCH (function_" + function_sha256 + ":Function {sha256:'" + function_sha256 + \
            "'}), (function_" + function_sha256_target + \
            ":Function {sha256:'" + function_sha256_target + "'})\n"
        query += "CREATE (function_" + function_sha256 + ")-[:SIMILAR_TO {similarity:" + \
            str(similarity) + "}]->(function_" + function_sha256_target + ")\n"

        return query

    def create_query_sample_has_function(self, sample_sha256,
                                         function_sha256):
        query = ""
        query += "(" + sample_sha256 + ")-[:HAS]->(" + function_sha256 + ")"
        return query


class Sample:
    def __init__(self, md5="", sha256="", functions=[], strings=[], imports=[],
                 exports=[], arch="", bits=0):
        self.md5 = md5
        self.sha256 = sha256
        self.functions = functions
        self.strings = strings
        self.imports = imports
        self.exports = exports
        self.arch = arch
        self.bits = bits
        return


class Function:
    def __init__(self, md5="", sha256="", size=0, arch="",
                 bits=0, call_refs=[]):
        self.md5 = md5
        self.sha256 = sha256
        self.size = size
        self.arch = arch
        self.bits = bits
        self.call_refs = call_refs
        return


@app.route('/')
def serve_index():
    return app.send_static_file('index.html')


def calculate_functions_similarity(filename_fct_analysed,
                                   filename_fct_compared_to):
    if filename_fct_analysed != filename_fct_compared_to:
        try:
            path_fct_analysed = FUNCTIONS_PATH + filename_fct_analysed
            path_fct_compared_to = FUNCTIONS_PATH + filename_fct_compared_to
            r2p = r2pipe.open('-')
            result_diff = r2p.cmd('!radiff2 -A -C -O ' +
                                  path_fct_analysed + " " + path_fct_compared_to)
            result_diff = result_diff.split('\n')
            result_diff = result_diff[-1].split('|')
            result_diff = re.sub(
                r'(.*)\(', '', result_diff[1]).replace(')', '')
            return float(result_diff)

        except:
            return 0.0

    else:
        return 0.0


def perform_analysis(binary_path):
    sample = Sample()
    r2p = r2pipe.open(binary_path)
    r2p.cmd('aaa')

    info = r2p.cmdj('iaj')
    sample.arch = info['info']['arch']
    sample.bits = info['info']['bits']
    sample.imports = info['imports']
    sample.exports = info['exports']
    function_offsets = r2p.cmdj('aflqj')
    sample.strings = r2p.cmdj('izzj')
    functions = []

    for offset in function_offsets:

        function_info = r2p.cmdj('afij @ ' + offset)[0]
        function_md5 = r2p.cmd(
            'ph md5 ' + str(function_info['size']) + ' @ ' + offset)
        function_sha256 = r2p.cmd(
            'ph sha256 ' + str(function_info['size']) + ' @ ' + offset)

        if not os.path.isfile(FUNCTIONS_PATH + function_sha256):
            if function_info['size'] >= THRESHOLD_FCT_SIZE:
                function = Function(
                    function_md5,
                    function_sha256,
                    function_info['size'],
                    sample.arch,
                    sample.bits,
                    function_info['callrefs'] if 'callrefs' in function_info else [])

                functions.append(function)

                open(FUNCTIONS_PATH + function_sha256, 'a').close()
                r2p.cmd('s ' + offset + ';wta ' + FUNCTIONS_PATH +
                        function.sha256 + ' $Fs @@c:afbq')

    sample.functions = functions

    return sample


def get_max_similarity(similarities_map):
    v = list(similarities_map.values())
    k = list(similarities_map.keys())
    try:
        return k[v.index(max(v))]
    except:
        return None


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


@app.route('/samples', methods=['POST'])
def post_sample():
    if 'file' not in request.files:
        return 'no file'

    file = request.files['file']
    if file.filename == '':
        return 'no file'

    tmp_file = tempfile.NamedTemporaryFile()
    file.save(tmp_file.name)
    md5, sha256 = checksums(tmp_file)
    sample = perform_analysis(tmp_file.name)
    if sample is not None:
        sample.md5 = md5.hexdigest()
        sample.sha256 = sha256.hexdigest()
        tmp_file.close()
        db = Neo4jDriver()
        query_new_node = db.create_query_new_node(sample)
        query_relationship = []

        for function in sample.functions:
            fct_found_in_db = False
            query_function_same_size = db.create_query_get_fct_same_size(
                function)
            functions_same_size = db.send_query(query_function_same_size)
            similarities = {}

            for fct_same_size in functions_same_size:
                fct_compared = fct_same_size[0]
                if fct_compared == function.sha256:
                    query_sample_has_function = db.create_query_sample_has_function(
                        sample.sha256, function.sha256)
                    query_relationship.append(query_sample_has_function)
                    fct_found_in_db = True
                    break
                else:
                    similarities[fct_compared] = calculate_functions_similarity(
                        function.sha256, fct_compared)

            if fct_found_in_db == False:
                fct_max_simil = get_max_similarity(similarities)
                if fct_max_simil is not None:
                    if similarities[fct_max_simil] >= THRESHOLD:
                        query_relationship.append(db.create_query_function_similar(
                            function.sha256, fct_max_simil, similarities[fct_max_simil]))

        db.send_query(query_new_node)

        print("FOUND SIMILAR! ", query_relationship)
        for query in query_relationship:
            db.send_query(query)
        db.close()
        return sample.md5 + " /// " + sample.sha256

    else:
        tmp_file.close()
        return "Error"


if __name__ == '__main__':
    app.run()

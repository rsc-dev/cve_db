#!/usr/bin/env python

__author__      = 'Radoslaw Matusiak'
__copyright__   = 'Copyright (c) 2017 Radoslaw Matusiak'
__license__     = 'MIT'
__version__     = '0.1'


"""
CVE vulnerabilities Python abstraction.
"""


import logging
import sqlite3
import sys


FORMAT = "%(asctime)-15s %(levelname)-10s %(name)-10s %(message)s"
logging.basicConfig(format=FORMAT)
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


DEFAULT_DB_NAME = 'cves.db'


def create_db(name):
    """Create CVE DB.
    
    Arguments:
    name -- Database name.
    """
    LOGGER.info('Creating database...')
    connection = None
    
    try:
        connection = sqlite3.connect(name)
        cursor = connection.cursor()
            
            
        # Create 'product' table 
        LOGGER.info('Creating table "product"')
        cursor.execute("""CREATE TABLE product (product_type TEXT, vendor TEXT, product TEXT, 
                        version TEXT, up TEXT, edition TEXT, language TEXT, UNIQUE(product, version, up, edition, language))""")
        
        # Create 'vulnerability' table 
        LOGGER.info('Creating table "vulnerability"')
        cursor.execute("""CREATE TABLE vulnerability (cve TEXT, description TEXT, cvss_score REAL,
                        confidentiality_impact INTEGER, integrity_impact INTEGER, availability_impact INTEGER,
                        access_complexity INTEGER, authentication INTEGER, gained_access INTEGER,
                        vulnerability_type INTEGER, cwe_id INTEGER, UNIQUE(cve))""")
        
        # Create 'vulnerability' table 
        LOGGER.info('Creating table "affected"')
        cursor.execute("""CREATE TABLE affected (cve TEXT, product_id INTEGER)""")
        
        # Create 'vulnerability' table 
        LOGGER.info('Creating table "strings"')
        cursor.execute("""CREATE TABLE strings (str TEXT, UNIQUE(str))""")
        
        connection.commit()
        connection.close()
        LOGGER.info('Done.')
    except sqlite3.Error as e:
        LOGGER.error('SQLITE error: {}'.format(str(e)))
        sys.exit(1)
# end-of-function create_db
    

class CVE_DB():
    """CVE DB helper class. Implements context manager methods."""
    
    def __init__(self, db_name=DEFAULT_DB_NAME):
        """Ctor.
        Arguments:
        db_name -- Database name. Default: cves.db.
        """
        LOGGER.debug('Creating CVE_BD instance with {}'.format(db_name))
        self.db_name = db_name
    # end-of-method __init__
    
    def __enter__(self):
        """Context manager __enter__ method.
        Open DB connection.
        """
        self.connection = None
        LOGGER.debug('Connecting to DB...')
        try:
            self.connection = sqlite3.connect(self.db_name)
            self.cursor = self.connection.cursor()
            
            LOGGER.debug('Connection established.')
        except sqlite3.Error as e:
            LOGGER.critical('Could not open DB: {}'.format(self.db_name))
            raise
        
        return self
    # end-of-method __enter__
    
    def __exit__(self, type, value, traceback):
        """Context manager __enter__ method.
        Close DB connection if opened.
        """
        if self.connection is not None:
            LOGGER.debug('Closing DB connection. Bye.')
            self.connection.close()
    # end-of-method __exit__
    
    def add_product(self, p):
        """Add Product instance to BD.
        
        Arguments:
        p -- Product instance.
        """
        assert self.cursor is not None, 'DB connection not set!'
        LOGGER.debug('Adding product={}; version={}.'.format(p.product, p.version))
        
        self.cursor.execute("""INSERT INTO 
                            product (product_type, vendor, product, version, up, edition, language) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)""", 
                            (p.product_type, p.vendor, p.product, p.version, p.update,
                            p.edition, p.language))
        
        return self.cursor.lastrowid
    # end-of-function add_product

    def add_vulnerability(self, v):
        """Add vulnerability to DB.
        
        Arguments:
        v -- Vulnerability instance.
        """
        assert self.cursor is not None, 'DB connection not set!'
        
        LOGGER.debug('Adding vulnerability CVE={}.'.format(v.cve))
        
        confidentiality_impact_id   = self.get_string_id(v.confidentiality_impact)
        integrity_impact_id         = self.get_string_id(v.integrity_impact)
        availability_impact_id      = self.get_string_id(v.availability_impact)
        access_complexity_id        = self.get_string_id(v.access_complexity)
        authentication_id           = self.get_string_id(v.authentication)
        gained_access_id            = self.get_string_id(v.gained_access)
        vulnerability_type_id       = self.get_string_id(v.vulnerability_type)
        
        self.cursor.execute("""INSERT INTO 
                            vulnerability (cve, description, cvss_score, confidentiality_impact, integrity_impact, availability_impact,
                            access_complexity, authentication, gained_access, vulnerability_type, cwe_id) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (v.cve, v.description, v.cvss_score, confidentiality_impact_id,
                            integrity_impact_id, availability_impact_id, access_complexity_id,
                            authentication_id, gained_access_id, vulnerability_type_id, v.cwe_id))
                            
        for p in v.products:
            p_id = self.add_product(p)
            
            self.cursor.execute("""INSERT INTO affected (cve, product_id) VALUES (?, ?)""", (v.cve, p_id))
            
        self.connection.commit()
    # end-of-function add_vulnerability
    
    def get_string_id(self, string):
        """Get string id from DB.
        
        Arguments:
        string -- String value.
        """
        assert self.cursor is not None, 'DB connection not set!'
        LOGGER.debug('Looking for string={}.'.format(string))
        
        if string is None:
            return ''
        
        self.cursor.execute("""SELECT rowid FROM strings WHERE str = ?""", (string,))
        str_id = self.cursor.fetchone()
        
        if str_id is None:
            LOGGER.debug('String not found. Adding to DB.')
        
            self.cursor.execute("""INSERT INTO strings (str) VALUES (?)""", (string, ))
            str_id = self.cursor.lastrowid
        else:
            LOGGER.debug('String found in DB.')
            str_id = int(str_id)
            
        return str_id
    # end-of-method get_string_id
    
    def get_string_by_id(self, id):
        """Get string from DB by id (rowid).
        
        Arguments:
        id -- String id (rowid).
        """
        assert self.cursor is not None, 'DB connection not set!'
        LOGGER.debug('Looking for string id={}.'.format(id))            
        
        self.cursor.execute("""SELECT str FROM strings WHERE rowid = ?""", (id,))
        str = self.cursor.fetchone()
        
        LOGGER.debug('String id={}; val={}.'.format(id, str))            
        
        return str if str is not None else ''
    # end-of-method get_string_by_id
    
    def get_vulnerability_by_cve(self, cve):
        """Get vulnerability dictionary from DB by CVE name.
        
        Arguments:
        cve -- CVE name. I.e.: CVE-2016-0001.
        """
        assert self.cursor is not None, 'DB connection not set!'
        LOGGER.debug('Looking for vulnerability: cve={}.'.format(cve))
        
        self.cursor.execute("""SELECT * FROM vulnerability WHERE cve = ?""", (cve,))
        vuln = self.cursor.fetchone()

        if vuln is not None:
            h = ('cve', 'description', 'cvss_score', 'confidentiality_impact', 'integrity_impact', 
                'availability_impact', 'access_complexity', 'authentication', 'gained_access',
                'vulnerability_type', 'cwe_id')
        
            vuln_d = dict(zip(h, vuln))
            # Fix string mappings.
            vuln_d['confidentiality_impact']    = self.get_string_by_id(vuln_d['confidentiality_impact'])
            vuln_d['integrity_impact']          = self.get_string_by_id(vuln_d['integrity_impact'])
            vuln_d['availability_impact']       = self.get_string_by_id(vuln_d['availability_impact'])
            vuln_d['access_complexity']         = self.get_string_by_id(vuln_d['access_complexity'])
            vuln_d['authentication']            = self.get_string_by_id(vuln_d['authentication'])
            vuln_d['gained_access']             = self.get_string_by_id(vuln_d['gained_access'])
            vuln_d['vulnerability_type']        = self.get_string_by_id(vuln_d['vulnerability_type'])
        else:
            LOGGER.debug('Looking for vulnerability: cve={}.'.format(cve))
            vuln_d = None
        
        return vuln_d
    # end-of-method get_vulnerability_by_cve
    
    def get_product_by_id(self, id):
        """Get product dictionary from DB by id (rowid).
        
        Arguments:
        id -- Product id (rowid).
        """
        assert self.cursor is not None, 'DB connection not set!'
        LOGGER.debug('Looking for product: id={}.'.format(id))
        
        self.cursor.execute("""SELECT * FROM product WHERE rowid = ?""", (id,))
        product = self.cursor.fetchone()

        if product is not None:
            h = ('product_type', 'vendor', 'product', 'version', 'update', 'edition', 'language')
        
            product_d = dict(zip(h, product))
        else:
            product_d = None
        
        return product_d
    # end-of-method get_product_by_id
    
    def get_affected_products_by_cve(self, cve):
        """Get list of product ids affected by given CVE.
        
        Arguments:
        cve -- CVE name.
        """
        assert self.cursor is not None, 'DB connection not set!'
        LOGGER.debug('Looking for affected products: cve={}.'.format(cve))
        
        self.cursor.execute("""SELECT product_id FROM affected WHERE cve = ?""", (cve,))
        
        return [id[0] for id in self.cursor.fetchall()]
    # end-of-method get_affected_products_by_cve
    
    pass
# end-of-class CVE_DB    
    
    
if __name__ == '__main__':
    if raw_input('Create empty DB [yes/no]: ') in ['y', 'yes']:
        create_db(DEFAULT_DB_NAME)

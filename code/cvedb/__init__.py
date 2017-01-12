#!/usr/bin/env python

__author__      = 'Radoslaw Matusiak'
__copyright__   = 'Copyright (c) 2017 Radoslaw Matusiak'
__license__     = 'MIT'
__version__     = '0.1'


"""
CVE vulnerabilities Python abstraction.
"""


import requests
import logging
from lxml import html

from db import CVE_DB

FORMAT = "%(asctime)-15s %(levelname)-10s %(name)-10s %(message)s"
logging.basicConfig(format=FORMAT)
LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


class Product:
    """Product class."""
    
    __slots__ = ['product_type', 'vendor', 'product', 'version',
                'update', 'edition', 'language']
    
    def __init__(self):
        """Ctor."""
        self.product_type   = None
        self.vendor         = None
        self.product        = None
        self.version        = None
        self.update         = None
        self.edition        = None
        self.language       = None
    # end-of-method __init__
    
    def from_dict(self, d):
        """Fill Product instance fields using dictionary.
        
        Arguments:
        d -- Dictionary with fields values.
        """
        for k in Product.__slots__:
            if k in d.keys():
                setattr(self, k, d[k])
    # end-of-method from_dict    
        
    pass
# end-of-class Product


class ProductBuilder:
    """Product builder class."""
    
    @staticmethod
    def get_product_from_xml(tr_element):
        """Parse TR element with product info from cvedetails.com.
        
        Arguments:
        tr_element -- TR element.
        """
        product = Product()
        
        product_xpath = 'normalize-space(td[{0}])'
        
        product.product_type    = tr_element.xpath(product_xpath.format(2))
        product.vendor          = tr_element.xpath(product_xpath.format(3))
        product.product         = tr_element.xpath(product_xpath.format(4))
        product.version         = tr_element.xpath(product_xpath.format(5))
        product.update          = tr_element.xpath(product_xpath.format(6))
        product.edition         = tr_element.xpath(product_xpath.format(7))
        product.language        = tr_element.xpath(product_xpath.format(8))

        return product
    # end-of-method get_product_from_xml
    
    pass
# end-of-class ProductBuilder  


class Vulnerability:
    """Vulnerability class."""

    __slots__ = ['cve', 'description', 'cvss_score', 'confidentiality_impact',
                'integrity_impact', 'availability_impact', 'access_complexity',
                'authentication', 'gained_access', 'vulnerability_type', 
                'cwe_id', 'products']
    
    
    def __init__(self, cve):
        """Ctor."""
        self.cve = cve
        
        self.description            = None
        self.cvss_score             = 0.0
        self.confidentiality_impact = None
        self.integrity_impact       = None
        self.availability_impact    = None
        self.access_complexity      = None
        self.authentication         = None
        self.gained_access          = None
        self.vulnerability_type     = None
        
        self.cwe_id = -1
        
        self.products = []
    # end-of-method __init__
    
    def add_product(self, product):
        """Add Product instance affected by this vulnerability.
        
        Arguments:
        product -- Product instance.
        """
        self.products.append(product)
    # end-of-method add_product
    
    def from_dict(self, d):
        """Fill Vulnerability instance fields using dictionary.
        
        Arguments:
        d -- Dictionary with fields values.
        """
        for k in Vulnerability.__slots__:
            if k in d.keys():
                setattr(self, k, d[k])
    # end-of-method from_dict
    
    def __str__(self):
        return '{} - CVSS score: {}; Affected products no: {}'.format(self.cve, self.cvss_score, len(self.products))
    
    pass
# end-of-class Vulnerability    


class VulnerabilityBuilder:
    """Vulnerability builder class."""
    
    CVE_DETAILS = 'http://www.cvedetails.com/cve/{}/'
    
    @staticmethod
    def get_vulnerability_by_cve_net(cve):
        """Get Vulnerability instance from cvedetails.com.
        If vulnerability is not found - returns None.
        
        Arguments:
        cve -- CVE name, i.e.: 'CVE-2016-0001'.
        """
        r = requests.get(VulnerabilityBuilder.CVE_DETAILS.format(cve))
        if r.status_code == 200:
            tree = html.fromstring(r.content)
           
            v = Vulnerability(cve)
            v.description = tree.xpath('//*[@id="cvedetails"]/div[1]/text()')[0]  # Description
            
            # Parse CVSS score table
            cvss_score = 'normalize-space(//*[@id="cvssscorestable"]/tr[{0}]/td[1])';  # CVSS score XPATH template
            
            v.cvss_score                = tree.xpath(cvss_score.format(1))
            v.confidentiality_impact    = tree.xpath(cvss_score.format(2))
            v.integrity_impact          = tree.xpath(cvss_score.format(3))
            v.availability_impact       = tree.xpath(cvss_score.format(4))
            v.access_complexity         = tree.xpath(cvss_score.format(5))
            v.authentication            = tree.xpath(cvss_score.format(6))
            v.gained_access             = tree.xpath(cvss_score.format(7))
            
            v.vulnerability_type        = tree.xpath(cvss_score.format(8))
            v.cwe_id                    = tree.xpath(cvss_score.format(9))
            
            # Parse affected products table
            affected = tree.xpath('//*[@id="vulnprodstable"]/tr')
            for tr_element in affected[1:]:
                product = ProductBuilder.get_product_from_xml(tr_element)
                v.add_product(product)
            
            return v
        # end-of-method get_vulnerability_by_cve
    
    @staticmethod
    def get_vulnerability_by_cve_db(db, cve):
        """Get Vulnerability instance from CVE DB by CVE name.
        If vulnerability is not found - returns None.
        
        Arguments:
        db -- CVE Database helper class instance.
        cve -- CVE name, i.e.: 'CVE-2016-0001'.
        """
        assert isinstance(db, CVE_DB), 'Invalid type of DB parameter!'
        LOGGER.debug('Looking for CVE: {} in DB.'.format(cve))
        
        v = db.get_vulnerability_by_cve(cve)
        
        if v is not None:
            LOGGER.debug('Vulnerability {} found in DB.'.format(cve))
            vulnerability = Vulnerability(cve)
            
            # Fetch vulnerability dictionary
            v = db.get_vulnerability_by_cve(cve)
            vulnerability.from_dict(v)
            # Fetch products affected by given vulnerability
            products_ids = db.get_affected_products_by_cve(cve)

            # Fill affected products list 
            for product_id in products_ids:
                product = Product()
                p = db.get_product_by_id(product_id)
                product.from_dict(p)
                
                vulnerability.add_product(product)
                
            return vulnerability
        else:
            LOGGER.debug('Vulnerability not found in DB.')
            return None
    # end-of-method get_vulnerability_by_cve_db
    
    pass
# end-of-class VulnerabilityBuilder    



def test():
    TEST_CVE = 'CVE-2016-1010'
    TEST_CVE_INVALID = 'xxx'
    #v = VulnerabilityBuilder.get_vulnerability_by_cve('CVE-2016-1010')
    
    #with CVE_DB() as db:
    #    db.add_vulnerability(v)
    
    with CVE_DB() as db:
        v = VulnerabilityBuilder.get_vulnerability_by_cve_db(db, TEST_CVE)
        print v.__dict__
        
        v = VulnerabilityBuilder.get_vulnerability_by_cve_db(db, TEST_CVE_INVALID)
# end-of-method test    


##
#  Entry point
if __name__ == '__main__':
    test()
    
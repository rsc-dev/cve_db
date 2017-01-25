# CVE DB

## About
CVE DB is a sqlite DB with CVEs and Python API.
CVEs are scrapped from [CVE Details](https://www.cvedetails.com/).

Latest DB is from 17.01.2017.

## Why?
It seems there is no developer friendly CVE data available.

## Usage
### DB
Download latest sqlite DB from [dbs](https://github.com/rsc-dev/cve_db/tree/master/dbs) and extract.

### Python
#### Updating DB
```python
with open('csv_list.txt', 'r') as csv_h:
        with CVE_DB() as db:
            for cve_name in csv_h:
                cve = cve_name.strip()
                v = VulnerabilityBuilder.get_vulnerability_by_cve_net(cve)
                if v is not None:
                    db.add_vulnerability(v)
```

#### DB lookup 
```python
with CVE_DB('db_file_name') as db:
    v = VulnerabilityBuilder.get_vulnerability_by_cve_db(db, 'CVE-2014-6271')
    print v.__dict__
```


## License
Code is released under [MIT license](https://github.com/rsc-dev/cve_db/blob/master/LICENSE) © [Radoslaw '[rsc]' Matusiak](https://rm2084.blogspot.com/).
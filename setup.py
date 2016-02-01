"""
Bottle-Kerberos
--------------

Provides Kerberos authentication support for PyBottle applications

Links
`````

* `development version
  <http://github.com/martinrm77/bottle-kerberos/zipball/master#egg=Bottle-Kerberos-dev>`_

"""

from setuptools import setup

setup(name='Bottle-Kerberos',
      version='1.0.0',
      url='http://github.com/martinrm77/bottle-kerberos',
      license='BSD',
      author='Michael Komitee, Martin Mortensen',
      author_email='martin.rene.mortensen@gmail.com',
      description='Kerberos authentication support for Bottle',
      long_description=__doc__,
      py_modules=['bottle_kerberos'],
      zip_safe=False,
      include_package_data=True,
      package_data={'': ['LICENSE', 'AUTHORS']},
      platforms='any',
      install_requires=['Bottle', 'kerberos'],
      classifiers=['Development Status :: 4 - Beta',
                   'Environment :: Web Environment',
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python',
                   'Topic :: Internet :: WWW/HTTP',
                   'Topic :: Software Development :: Libraries :: Python Modules'],
      test_suite='test_bottle_kerberos',
      tests_require=['mock'])

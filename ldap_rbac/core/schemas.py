# -*- coding: utf-8 -*-
REGISTER_OBJECT_CLASSES = {
    'top': {},
    'organizationalUnit': {
        'MUST': ['ou'],
        'MAY': [
            'userPassword', 'searchGuide', 'seeAlso', 'businessCategory',
            'x121Address', 'registeredAddress', 'destinationIndicator',
            'preferredDeliveryMethod', 'telexNumber', 'teletexTerminalIdentifier',
            'telephoneNumber', 'internationaliSDNNumber',
            'facsimileTelephoneNumber', 'street', 'postOfficeBox', 'postalCode',
            'postalAddress', 'physicalDeliveryOfficeName', 'st', 'l', 'description'
        ]
    },
    'person': {
        'MUST': ['cn', 'sn'],
        'MAY': ['description', 'seeAlso', 'telephoneNumber', 'userPassword'],
    },
    'organizationalPerson': {
        'MAY': [
            'title',  'x121Address',  'registeredAddress',  'destinationIndicator',
            'preferredDeliveryMethod',  'telexNumber',  'teletexTerminalIdentifier',
            'telephoneNumber',  'internationaliSDNNumber',
            'facsimileTelephoneNumber',  'street',  'postOfficeBox',  'postalCode',
            'postalAddress',  'physicalDeliveryOfficeName',  'ou',  'st',  'l'
        ]
    },
    'organizationalRole': {
        'MUST': ['cn'],
        'MAY': [
            'x121Address', 'registeredAddress', 'destinationIndicator',
            'preferredDeliveryMethod', 'telexNumber', 'teletexTerminalIdentifier',
            'telephoneNumber', 'internationaliSDNNumber', 'facsimileTelephoneNumber',
            'seeAlso', 'roleOccupant', 'preferredDeliveryMethod', 'street',
            'postOfficeBox', 'postalCode', 'postalAddress',
            'physicalDeliveryOfficeName', 'ou', 'st', 'l', 'description'
        ]
    },
    'inetOrgPerson': {
        'MAY': [
            'audio', 'businessCategory', 'carLicense', 'departmentNumber',
            'displayName', 'employeeNumber', 'employeeType', 'givenName',
            'homePhone', 'homePostalAddress', 'initials', 'jpegPhoto',
            'labeledURI', 'mail', 'manager', 'mobile', 'o', 'pager', 'photo',
            'roomNumber', 'secretary', 'uid', 'userCertificate',
            'x500uniqueIdentifier', 'preferredLanguage',
            'userSMIMECertificate', 'userPKCS12'
        ]
    },
    'device': {
        'MUST': ['cn'],
        'MAY': ['description', 'l', 'o', 'ou', 'owner', 'seeAlso', 'serialNumber']
    },
    'ftMods ':{
        'MAY': ['ftModifier', 'ftModCode', 'ftModId']
    },
    'ftProperties': {
        'MAY': ['ftProps']
    },
    'ftUserAttrs':{
        'MUST': ['ftId'],
        'MAY': ['ftRC', 'ftRA', 'ftARC', 'ftARA', 'ftCstr', 'ftSystem']
    },
    'ftRls': {
        'MUST': ['ftId', 'ftRoleName'],
        'MAY': ['description', 'ftCstr', 'ftParents']
    },
    'ftPools': {
        'MAY': ['ftOSU', 'ftOSP', 'ftRange']
    },
    'ftOrgUnit': {
        'MUST': ['ftProps'],
        'MAY': ['ftParents']
    },
    'ftOperation': {
        'MUST': ['ftId', 'ftPermName', 'ftObjNm', 'ftOpNm'],
        'MAY': ['ftObjId', 'ftRoles', 'ftUsers', 'ftType']
    },
    'ftObject': {
        'MUST': ['ftId', 'ftObjNm'],
        'MAY': ['ftType']
    },
    'groupOfNames': {
        'MUST': ['cn', 'member'],
        'MAY': ['businessCategory', 'description', 'o', 'ou', 'owner', 'seeAlso']
    }
}


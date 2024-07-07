from django.urls import reverse

menu = {
    'module_system': {
        'child': [
            {
                'name': 'system_firewalld',
                'title': '防火墙',
                'href': reverse('module_system:system_firewalld:port-list'),
            },
        ]
    }
}

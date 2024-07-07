from django.apps import AppConfig


class SystemFirewalldConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.system_firewalld'
    verbose_name = '防火墙相关管理'
    dependent_modules = ['module_system']
    version = '0.0.1-Alpha'
    description = '使用简易的方式管理系统防火墙的端口等设置'

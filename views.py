import subprocess
import re
import json
from pathlib import Path

from xml.etree import ElementTree

from django.conf import settings
from django.utils import timezone
from django.http import JsonResponse
from django.contrib import messages
from django.urls import reverse, reverse_lazy
from django.views.generic.list import ListView
from django.views.generic.base import TemplateView, RedirectView
from django.views.generic.edit import FormView, UpdateView
from django.views.generic.edit import CreateView

from appcommon.helper import subprocess_run, read_file, write_file, make_dir
from panel.module_system.views import ModuleSystemMixin

from .models import Ports
from .forms import PortsForm
from .conf import default_port

reload_exec_statement = 'firewall-cmd --reload'


def diff_panel_ports_file():
    return Path.joinpath(make_dir(Path.joinpath(settings.MEDIA_ROOT, 'system_firewalld')), 'diff_panel_ports.json')


def reload_firewalld():
    return subprocess_run(subprocess, reload_exec_statement)


def install_run(request):
    exec_statement = 'dnf install -y firewalld'
    run_end = subprocess_run(subprocess, exec_statement)
    return_dict = {'run_end': run_end.returncode,
                   'showprocess': (run_end.stdout + run_end.stderr).replace('\n', '</br>')}
    return JsonResponse(return_dict, safe=False)


def set_default_port(port):
    if port in default_port:
        return default_port[port]
    else:
        return ''


def firewalld_status(request):
    action = int(request.GET.get('action'))
    exec_statement = ''

    if action == 0:
        # 停止
        exec_statement = 'systemctl stop firewalld && systemctl disable firewalld'
    if action == 1:
        # 启动
        exec_statement = 'systemctl start firewalld && systemctl enable firewalld'
    if action == 2:
        # 重载
        exec_statement = reload_exec_statement
    if action == 3:
        # 重载
        exec_statement = 'systemctl restart firewalld'

    if exec_statement:
        run_end = subprocess_run(subprocess, exec_statement)
        return_dict = {'returncode': run_end.returncode, 'stdout': run_end.stdout, 'stderr': run_end.stderr}
    else:
        return_dict = {'returncode': 1,  'stdout': '', 'stderr': '参数错误！无法正常执行！'}

    return JsonResponse(return_dict, safe=False)


def ping_action(request):
    action = int(request.GET.get('action'))
    filename = '/etc/sysctl.conf'
    conf = read_file(filename)
    if conf.find('net.ipv4.icmp_echo') != -1:
        rep = u"net\.ipv4\.icmp_echo.*"
        conf = re.sub(rep, 'net.ipv4.icmp_echo_ignore_all={}'.format(action), conf)
    else:
        conf += "\nnet.ipv4.icmp_echo_ignore_all={}".format(action)
    write_file(filename, conf)
    run_end = subprocess_run(subprocess, 'sysctl -p')
    return_dict = {'returncode': run_end.returncode, 'stdout': run_end.stdout, 'stderr': run_end.stderr}
    return JsonResponse(return_dict, safe=False)


def get_system_ports():
    """ 获取redhat系统中public区域的端口信息 """
    conf_file = '/etc/firewalld/zones/public.xml'
    tree = ElementTree.parse(conf_file)
    try:
        root = tree.getroot()
    except:
        root = []
    data = {}
    if len(root) < 1:
        return data
    i = 1
    for p in root:
        tmp = {}
        if p.tag == 'port':
            tmp["protocol"] = p.attrib['protocol']
            tmp['ports'] = p.attrib['port']
            tmp['types'] = 'accept'
            tmp['address'] = ''
        # elif p.tag == 'forward-port':
        #     tmp["protocol"] = p.attrib['protocol']
        #     tmp["port"] = p.attrib['port']
        #     tmp["address"] = p.attrib.get('to-addr', '')
        #     tmp["to-port"] = p.attrib['to-port']
        #     arry.append(tmp)
        #     continue
        elif p.tag == 'rule':
            tmp["types"] = 'accept'
            tmp['ports'] = ''
            tmp['protocol'] = ''
            # ch = p.getchildren()
            for c in p.iter():
                if c.tag == 'port':
                    tmp['protocol'] = c.attrib['protocol']
                    tmp['ports'] = c.attrib['port']
                elif c.tag == 'drop':
                    tmp['types'] = 'drop'
                elif c.tag == 'reject':
                    tmp['types'] = 'reject'
                elif c.tag == 'source':
                    if "address" in c.attrib.keys():
                        tmp['address'] = c.attrib['address']
                if "address" not in tmp:
                    tmp['address'] = ''
        else:
            continue
        if tmp:
            data[i] = tmp
            i += 1
    return data


def get_panel_ports():
    get_ports = Ports.objects.filter().all()
    get_list = {}
    for port in get_ports:
        get_list[port.id] = {
            'protocol': port.protocol,
            'ports': port.ports,
            'types': port.types,
            'address': port.address
            }
    return get_list


def check_diff(list1, list2):
    diff_data = []
    for k, v in list1.items():
        if v not in list2.values():
            v.update({'id': k})
            diff_data.append(v)
    return diff_data


def port_system_create(**kwargs):
    protocol = kwargs['protocol'].strip()
    ports = kwargs['ports'].strip()
    types = kwargs['types'].strip()

    address = ''
    if 'address' in kwargs:
        address = kwargs['address'].strip()

    exec_statement = ''
    if address:
        exec_statement = (f'firewall-cmd --permanent --add-rich-rule=\'rule family="ipv4" '
                          f'source address="{address}" '
                          f'port protocol="{protocol}" port="{ports}" {types}\'')
    else:
        if types == 'accept':
            exec_statement = f'firewall-cmd --add-port={ports}/{protocol} --permanent'
        if types == 'drop':
            exec_statement = (f'firewall-cmd --permanent --add-rich-rule=\'rule family="ipv4" '
                              f'port protocol="{protocol}" port="{ports}" {types}\'')

    return subprocess_run(subprocess, exec_statement)


def port_system_del(**kwargs):
    protocol = kwargs['protocol']
    ports = kwargs['ports']
    types = kwargs['types']

    address = ''
    if 'address' in kwargs:
        address = kwargs['address']

    exec_statement = ''
    if address:
        exec_statement = (f'firewall-cmd --permanent --remove-rich-rule=\'rule family="ipv4" '
                          f'source address="{address}" '
                          f'port protocol="{protocol}" port="{ports}" {types}\'')
    else:
        if types == 'accept':
            exec_statement = f'firewall-cmd --permanent --remove-port={ports}/{protocol}'
        if types == 'drop':
            exec_statement = (f'firewall-cmd --permanent --remove-rich-rule=\'rule family="ipv4" '
                              f'port protocol="{protocol}" port="{ports}" {types}\'')

    return subprocess_run(subprocess, exec_statement)


class FirewallMixin(ModuleSystemMixin):
    """ 防火墙栏目基础参数 """
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['menu'] = 'system_firewalld'
        context['running'] = '1'
        firewall_state = subprocess_run(subprocess, 'firewall-cmd --state')
        if firewall_state.stdout.strip().strip("\n") == "running":
            context['running'] = '1'
        elif firewall_state.stderr.strip().strip("\n") == "not running":
            context['running'] = '2'
        else:
            context['running'] = '0'
        context['ping'] = subprocess_run(
            subprocess, 'cat /proc/sys/net/ipv4/icmp_echo_ignore_all'
        ).stdout.strip("\n")
        return context


class InstallView(FirewallMixin, TemplateView):
    template_name = 'system_firewalld/install.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = '防火墙安装'
        context['breadcrumb'] = [
            {'title': '防火墙端口管理', 'href': reverse_lazy('module_system:system_firewalld:port-list'), 'active': False},
            {'title': '防火墙安装', 'href': '', 'active': True},
        ]

        return context


class PortsMixin(FirewallMixin):
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['current_menu'] = 'ports'
        return context


class PortsListView(PortsMixin, ListView):
    model = Ports
    template_name = 'system_firewalld/port_list.html'
    paginate_by = 10
    ordering = ['-create_at']

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = '防火墙-端口规则'
        print(context['menu'])
        context['self_url'] = reverse('module_system:system_firewalld:port-list')
        return context


class PortsDelView(PortsMixin, RedirectView):

    def get(self, request, *args, **kwargs):
        try:
            get_object = Ports.objects.get(pk=self.kwargs['pk'])
            protocol = get_object.protocol
            ports = get_object.ports
            types = get_object.types
            address = get_object.address.strip()

            exec_statement = ''
            if address:
                exec_statement = 'firewall-cmd --permanent --remove-rich-rule=\'rule family="ipv4"'
                exec_statement += f' source address="{address}"'
                exec_statement += f' port protocol="{protocol}" port="{ports}" {types} \''
            else:
                if types == 'accept':
                    exec_statement = f'firewall-cmd --permanent --zone=public --remove-port={ports}/{protocol}'
                if types == 'drop':
                    exec_statement = 'firewall-cmd --permanent --remove-rich-rule=\'rule family="ipv4"'
                    exec_statement += f' port protocol="{protocol}" port="{ports}" {types} \''
            run = subprocess_run(subprocess, exec_statement)
            if run.returncode == 0:
                Ports.objects.filter(pk=self.kwargs['pk']).delete()
                reload_firewalld()
                messages.success(request, f'端口{ports}已删除！')
            else:
                messages.warning(request, f'服务器删除端口不成功! {run.stdout}{run.stderr}')

        except Ports.DoesNotExist or Ports.MultipleObjectsReturned:
            messages.warning(request, message='没有找到要执行的端口信息！')

        return super().get(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return reverse_lazy('module_system:system_firewalld:port-list')


class PortsCreateView(PortsMixin, FormView):
    form_class = PortsForm
    template_name = 'system_firewalld/port_form.html'
    success_url = reverse_lazy('module_system:system_firewalld:port-list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['self_url'] = reverse('module_system:system_firewalld:port-list')
        context['page_title'] = '防火墙-创建端口规则'
        context['breadcrumb'] = [
            {'title': '防火墙端口规则', 'href': reverse_lazy('module_system:system_firewalld:port-list'), 'active': False},
            {'title': '创建端口规则', 'href': '', 'active': True},
        ]
        return context

    def form_valid(self, form):
        protocol = form.cleaned_data['protocol'].strip()
        get_ports = form.cleaned_data['ports'].strip()
        types = form.cleaned_data['types'].strip()
        get_address = form.cleaned_data['address']
        description = form.cleaned_data['description'].strip()

        ip_list = get_address.replace(' ', '').replace('，',',').split(',')
        ports_list = get_ports.replace(' ', '').replace('，',',').split(',')

        if len(ip_list):
            for ports in ports_list:
                for address in ip_list:
                    address = address.strip()
                    run = port_system_create(protocol=protocol, ports=ports, types=types, address=address)
                    if description == '':
                        description = set_default_port(ports)
                    if run.returncode == 0:
                        Ports.objects.create(
                            protocol=protocol, ports=ports, types=types, address=address.strip(),
                            description=description, create_at=timezone.now()
                        )
                        reload_firewalld()
                    else:
                        messages.warning(self.request, f'服务器创建端口 {ports} 端口操作失败! {run.stdout}{run.stderr}')
                        self.success_url = reverse('module_system:system_firewalld:port_create')
        else:
            for ports in ports_list:
                ports = ports.strip()
                run = port_system_create(protocol=protocol, ports=ports, types=types)
                if description == '':
                    description = set_default_port(ports)
                if run.returncode == 0:
                    Ports.objects.create(
                        protocol=protocol, ports=ports, types=types,
                        description=description, create_at=timezone.now()
                    )
                else:
                    messages.warning(self.request, f'服务器创建端口 {ports} 操作失败! {run.stdout}{run.stderr}')
                    self.success_url = reverse('module_system:system_firewalld:port_create')

        return super().form_valid(form)


class PortsEditView(PortsMixin, FormView):
    form_class = PortsForm
    template_name = 'system_firewalld/port_form.html'
    success_url = reverse_lazy('module_system:system_firewalld:port-list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['self_url'] = reverse('module_system:system_firewalld:port_edit', kwargs={'pk': self.kwargs['pk']})
        context['page_title'] = '防火墙-修改端口规则'
        context['breadcrumb'] = [
            {'title': '防火墙端口规则', 'href': reverse_lazy('module_system:system_firewalld:port-list'), 'active': False},
            {'title': '修改端口规则', 'href': '', 'active': True},
        ]
        return context

    def get_initial(self):
        self.initial = super().get_initial()
        get_object = Ports.objects.get(pk=self.kwargs['pk'])
        self.initial['protocol'] = get_object.protocol
        self.initial['ports'] = get_object.ports
        self.initial['types'] = get_object.types
        self.initial['address'] = get_object.address
        self.initial['description'] = get_object.description
        if self.initial['address']:
            self.initial['ip_source'] = 'ip'
        else:
            self.initial['ip_source'] = 'all'
        return self.initial.copy()

    def form_valid(self, form):
        if form.has_changed():
            protocol = form.cleaned_data['protocol'].strip()
            ports = form.cleaned_data['ports'].strip()
            types = form.cleaned_data['types'].strip()
            get_address = form.cleaned_data['address']
            description = form.cleaned_data['description'].strip()

            get_object = Ports.objects.get(pk=self.kwargs['pk'])
            # 删除服务器上旧的端口配置,删除数据库数据
            obj_protocol = get_object.protocol
            obj_ports = get_object.ports
            obj_types = get_object.types
            obj_address = get_object.address
            port_system_del(protocol=obj_protocol, ports=obj_ports, types=obj_types, address=obj_address)
            Ports.objects.get(pk=self.kwargs['pk']).delete()

            # 拆分重新添加规则
            ip_list = get_address.replace(' ', '').replace('，',',').split(',')

            if len(ip_list):
                for address in ip_list:
                    address = address.strip()
                    run = port_system_create(protocol=protocol, ports=ports, types=types, address=address)
                    if description == '':
                        description = set_default_port(ports)
                    if run.returncode == 0:
                        Ports.objects.create(
                            protocol=protocol, ports=ports, types=types, address=address.strip(),
                            description=description, create_at=timezone.now()
                        )
                        reload_firewalld()
                    else:
                        messages.warning(self.request,
                                         f'服务器创建端口 {ports} 端口操作失败! {run.stdout}{run.stderr}')
                        self.success_url = reverse('module_system:system_firewalld:port_create')
            else:
                ports = ports.strip()
                run = port_system_create(protocol=protocol, ports=ports, types=types)
                if description == '':
                    description = set_default_port(ports)
                if run.returncode == 0:
                    Ports.objects.create(
                        protocol=protocol, ports=ports, types=types,
                        description=description, create_at=timezone.now()
                    )
                else:
                    messages.warning(self.request, f'服务器创建端口 {ports} 操作失败! {run.stdout}{run.stderr}')
                    self.success_url = reverse('module_system:system_firewalld:port_create')

        return super().form_valid(form)


class CheckSystemPortsView(PortsMixin, ListView):
    model = Ports
    template_name = 'system_firewalld/check_ports.html'
    paginate_by = 10

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = '防火墙-检测端口同步配置'
        context['self_url'] = reverse(
            'module_system:system_firewalld:check_ports', kwargs={'type_at': self.kwargs['type_at']}
        )
        context['type_at'] = self.kwargs['type_at']
        context['breadcrumb'] = [
            {'title': '防火墙端口规则', 'href': reverse_lazy('module_system:system_firewalld:port-list'), 'active': False},
            {'title': '检测端口配置', 'href': '', 'active': True},
        ]
        context['check_sys_count'] = len(check_diff(get_panel_ports(), get_system_ports()))
        context['check_panel_count'] = len(check_diff(get_system_ports(), get_panel_ports()))
        return context

    def get_queryset(self):
        get_diff = []
        if self.kwargs['type_at'] == 1:
            get_diff = check_diff(get_panel_ports(), get_system_ports())
        if self.kwargs['type_at'] == 2:
            get_diff = check_diff(get_system_ports(), get_panel_ports())
            file_path = diff_panel_ports_file()
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(get_diff, f, ensure_ascii=False)
            return get_diff
        return get_diff


class SyncPortsView(PortsMixin, RedirectView):

    def get(self, request, *args, **kwargs):
        type_at = self.kwargs['type_at']

        if type_at == 1:
            pk = self.kwargs['pk']
            try:
                get_object = Ports.objects.get(pk=pk)
                protocol = get_object.protocol.strip()
                ports = get_object.ports.strip()
                types = get_object.types.strip()
                address = get_object.address.strip()

                run = port_system_create(protocol=protocol, ports=ports, types=types, address=address)
                if run.returncode == 0:
                    get_object.create_at = timezone.now()
                    get_object.save()
                    reload_firewalld()
                    messages.success(request, f'端口{get_object.ports}同步操作完成！')
                else:
                    messages.warning(request, message=f'同步到系统未成功! {run.stdout}{run.stderr}')
            except Ports.DoesNotExist or Ports.MultipleObjectsReturned:
                messages.warning(request, message='没有找到要执行的端口信息！')

        if type_at == 2:
            file_path = diff_panel_ports_file()
            with open(file_path, 'r', encoding='utf-8') as file:
                get_content = json.load(file)
            for item in get_content:
                if item['id'] == self.kwargs['pk']:
                    description = ''
                    if item['ports'] in default_port:
                        description = default_port[item['ports']]
                    Ports.objects.create(
                        protocol=item['protocol'],
                        ports=item['ports'],
                        types=item['types'],
                        address=item['address'],
                        description=description,
                        create_at=timezone.now()
                    )

        return super().get(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return reverse('module_system:system_firewalld:check_ports', kwargs={'type_at': self.kwargs['type_at']})


class SyncPortsDelView(PortsMixin, RedirectView):

    def get(self, request, *args, **kwargs):
        Ports.objects.get(pk=self.kwargs['pk']).delete()
        return super().get(request, *args, **kwargs)

    def get_redirect_url(self, *args, **kwargs):
        return reverse('module_system:system_firewalld:check_ports', kwargs={'type_at': self.kwargs['type_at']})


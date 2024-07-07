from django import forms

from appcommon.forms import FormBase

from .conf import protocol_choices


class PortsForm(FormBase):
    protocol = forms.CharField(label='*协议', widget=forms.Select(choices=protocol_choices))
    ports = forms.CharField(
        label='*端口', widget=forms.TextInput(
            attrs={
                'class': 'layui-input', 'lay-verify': 'required', 'autocomplete': 'off', 'lay-reqtext': '端口不能为空'
            }
        )
    )
    types = forms.CharField(
        label='*策略',
        widget=forms.Select(
            choices=(('accept', '允许'), ('drop', '拒绝')),
            attrs={'lay-verify': 'required', 'lay-reqtext': '策略不能为空'}
        )
    )
    ip_source = forms.CharField(
        label='*来源',
        widget=forms.Select(
            choices=(('all', '所有ip'), ('ip', '指定IP')),
            attrs={'lay-filter': 'select_source', 'lay-verify': 'required', 'lay-reqtext': '来源类型不能为空'}
        )
    )

    address = forms.CharField(
        label='指定IP', required=False, widget=forms.TextInput(
            attrs={'class': 'layui-input', 'autocomplete': 'off', 'lay-verify': 'ipOrIps'}
        )
    )
    description = forms.CharField(
        label='描述', required=False,
        widget=forms.Textarea(
            attrs={'class': 'layui-textarea', 'rows': '3'}
        )
    )



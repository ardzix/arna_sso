from django.urls import path

from .bnk_iam import BnkContextView, BnkMemberRolesView, BnkMembersView, BnkPermissionsView, BnkRoleDetailView, BnkRolesView


urlpatterns = [
    path('context/', BnkContextView.as_view(), name='bnk-iam-context'),
    path('permissions/', BnkPermissionsView.as_view(), name='bnk-iam-permissions'),
    path('roles/', BnkRolesView.as_view(), name='bnk-iam-roles'),
    path('roles/<str:role_id>/', BnkRoleDetailView.as_view(), name='bnk-iam-role'),
    path('members/', BnkMembersView.as_view(), name='bnk-iam-members'),
    path('members/<str:member_id>/roles/', BnkMemberRolesView.as_view(), name='bnk-iam-member-roles'),
]

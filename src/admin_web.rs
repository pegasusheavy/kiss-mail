//! KISS Admin Web Interface
//!
//! A simple web-based admin dashboard using Actix-web and Handlebars.
//! Styled with Tailwind CSS from CDN.

use actix_web::{HttpRequest, HttpResponse, cookie::Cookie, web};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::groups::GroupManager;
use crate::ldap::LdapClient;
use crate::sso::SsoManager;
use crate::users::{UserManager, UserRole};

/// Web admin configuration
#[derive(Debug, Clone)]
pub struct WebAdminConfig {
    pub enabled: bool,
    pub port: u16,
    pub bind_address: String,
}

impl Default for WebAdminConfig {
    fn default() -> Self {
        Self {
            enabled: std::env::var("KISS_MAIL_WEB_ENABLED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
            port: std::env::var("KISS_MAIL_WEB_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8080),
            bind_address: std::env::var("KISS_MAIL_WEB_BIND")
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
        }
    }
}

/// Shared state for web handlers
pub struct WebState {
    pub user_manager: Arc<UserManager>,
    pub group_manager: Arc<GroupManager>,
    pub ldap_client: Arc<LdapClient>,
    pub sso_manager: Arc<SsoManager>,
    pub hbs: Handlebars<'static>,
    pub domain: String,
}

// ============================================================================
// Templates (embedded for simplicity)
// ============================================================================

const BASE_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en" class="h-full bg-gray-50">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}} - KISS Mail Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#3b82f6',
                    }
                }
            }
        }
    </script>
    <style>
        .fade-in { animation: fadeIn 0.2s ease-in; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    </style>
</head>
<body class="h-full">
    <div class="min-h-full">
        <!-- Navigation -->
        <nav class="bg-white shadow-sm border-b border-gray-200">
            <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                <div class="flex h-16 justify-between">
                    <div class="flex">
                        <div class="flex flex-shrink-0 items-center">
                            <span class="text-xl font-bold text-gray-900">📧 KISS Mail</span>
                        </div>
                        <div class="hidden sm:ml-8 sm:flex sm:space-x-8">
                            <a href="/admin" class="{{#if nav_dashboard}}border-primary text-gray-900{{else}}border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700{{/if}} inline-flex items-center border-b-2 px-1 pt-1 text-sm font-medium">
                                Dashboard
                            </a>
                            <a href="/admin/users" class="{{#if nav_users}}border-primary text-gray-900{{else}}border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700{{/if}} inline-flex items-center border-b-2 px-1 pt-1 text-sm font-medium">
                                Users
                            </a>
                            <a href="/admin/groups" class="{{#if nav_groups}}border-primary text-gray-900{{else}}border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700{{/if}} inline-flex items-center border-b-2 px-1 pt-1 text-sm font-medium">
                                Groups
                            </a>
                        </div>
                    </div>
                    <div class="flex items-center">
                        <span class="text-sm text-gray-500 mr-4">{{username}}</span>
                        <a href="/admin/logout" class="text-sm text-gray-500 hover:text-gray-700">Logout</a>
                    </div>
                </div>
            </div>
        </nav>

        <!-- Main content -->
        <main class="fade-in">
            <div class="mx-auto max-w-7xl py-6 px-4 sm:px-6 lg:px-8">
                {{#if flash_success}}
                <div class="mb-4 rounded-md bg-green-50 p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <svg class="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-green-800">{{flash_success}}</p>
                        </div>
                    </div>
                </div>
                {{/if}}
                {{#if flash_error}}
                <div class="mb-4 rounded-md bg-red-50 p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-red-800">{{flash_error}}</p>
                        </div>
                    </div>
                </div>
                {{/if}}
                {{{content}}}
            </div>
        </main>
    </div>
</body>
</html>"#;

const LOGIN_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en" class="h-full bg-gray-50">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - KISS Mail Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="h-full">
    <div class="flex min-h-full flex-col justify-center py-12 sm:px-6 lg:px-8">
        <div class="sm:mx-auto sm:w-full sm:max-w-md">
            <h1 class="text-center text-3xl font-bold text-gray-900">📧 KISS Mail</h1>
            <h2 class="mt-2 text-center text-xl text-gray-600">Admin Dashboard</h2>
        </div>

        <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
            <div class="bg-white py-8 px-4 shadow-lg sm:rounded-lg sm:px-10 border border-gray-200">
                {{#if error}}
                <div class="mb-4 rounded-md bg-red-50 p-4">
                    <p class="text-sm text-red-800">{{error}}</p>
                </div>
                {{/if}}
                
                <form class="space-y-6" action="/admin/login" method="POST">
                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                        <div class="mt-1">
                            <input id="username" name="username" type="text" autocomplete="username" required
                                class="block w-full appearance-none rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-blue-500 sm:text-sm">
                        </div>
                    </div>

                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                        <div class="mt-1">
                            <input id="password" name="password" type="password" autocomplete="current-password" required
                                class="block w-full appearance-none rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-blue-500 sm:text-sm">
                        </div>
                    </div>

                    <div>
                        <button type="submit"
                            class="flex w-full justify-center rounded-md border border-transparent bg-blue-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
                            Sign in
                        </button>
                    </div>
                </form>
            </div>
        </div>
        
        <p class="mt-8 text-center text-sm text-gray-500">
            KISS Mail Server v{{version}}
        </p>
    </div>
</body>
</html>"#;

const DASHBOARD_CONTENT: &str = r#"
<div class="mb-8">
    <h1 class="text-2xl font-bold text-gray-900">Dashboard</h1>
    <p class="mt-1 text-sm text-gray-500">Server overview for {{domain}}</p>
</div>

<!-- Stats -->
<div class="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
    <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow border border-gray-200">
        <dt class="truncate text-sm font-medium text-gray-500">Total Users</dt>
        <dd class="mt-1 text-3xl font-semibold tracking-tight text-gray-900">{{stats.users}}</dd>
    </div>
    <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow border border-gray-200">
        <dt class="truncate text-sm font-medium text-gray-500">Groups</dt>
        <dd class="mt-1 text-3xl font-semibold tracking-tight text-gray-900">{{stats.groups}}</dd>
    </div>
    <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow border border-gray-200">
        <dt class="truncate text-sm font-medium text-gray-500">Active Users</dt>
        <dd class="mt-1 text-3xl font-semibold tracking-tight text-gray-900">{{stats.active_users}}</dd>
    </div>
    <div class="overflow-hidden rounded-lg bg-white px-4 py-5 shadow border border-gray-200">
        <dt class="truncate text-sm font-medium text-gray-500">Admins</dt>
        <dd class="mt-1 text-3xl font-semibold tracking-tight text-gray-900">{{stats.admins}}</dd>
    </div>
</div>

<!-- System Status -->
<div class="mt-8">
    <h2 class="text-lg font-medium text-gray-900 mb-4">System Status</h2>
    <div class="overflow-hidden rounded-lg bg-white shadow border border-gray-200">
        <ul role="list" class="divide-y divide-gray-200">
            <li class="px-4 py-4 sm:px-6">
                <div class="flex items-center justify-between">
                    <p class="text-sm font-medium text-gray-900">LDAP Authentication</p>
                    {{#if ldap_enabled}}
                    <span class="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                        Enabled
                    </span>
                    {{else}}
                    <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-0.5 text-xs font-medium text-gray-800">
                        Disabled
                    </span>
                    {{/if}}
                </div>
            </li>
            <li class="px-4 py-4 sm:px-6">
                <div class="flex items-center justify-between">
                    <p class="text-sm font-medium text-gray-900">SSO Provider</p>
                    {{#if sso_enabled}}
                    <span class="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                        {{sso_provider}}
                    </span>
                    {{else}}
                    <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-0.5 text-xs font-medium text-gray-800">
                        Disabled
                    </span>
                    {{/if}}
                </div>
            </li>
            <li class="px-4 py-4 sm:px-6">
                <div class="flex items-center justify-between">
                    <p class="text-sm font-medium text-gray-900">Server Version</p>
                    <span class="text-sm text-gray-500">{{version}}</span>
                </div>
            </li>
        </ul>
    </div>
</div>

<!-- Quick Actions -->
<div class="mt-8">
    <h2 class="text-lg font-medium text-gray-900 mb-4">Quick Actions</h2>
    <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <a href="/admin/users/new" class="relative block rounded-lg border border-gray-300 bg-white px-6 py-4 shadow-sm hover:border-gray-400 focus:outline-none">
            <span class="text-lg">👤</span>
            <span class="ml-2 text-sm font-medium text-gray-900">Create User</span>
        </a>
        <a href="/admin/groups/new" class="relative block rounded-lg border border-gray-300 bg-white px-6 py-4 shadow-sm hover:border-gray-400 focus:outline-none">
            <span class="text-lg">👥</span>
            <span class="ml-2 text-sm font-medium text-gray-900">Create Group</span>
        </a>
        <a href="/admin/users" class="relative block rounded-lg border border-gray-300 bg-white px-6 py-4 shadow-sm hover:border-gray-400 focus:outline-none">
            <span class="text-lg">📋</span>
            <span class="ml-2 text-sm font-medium text-gray-900">Manage Users</span>
        </a>
    </div>
</div>
"#;

const USERS_CONTENT: &str = r#"
<div class="sm:flex sm:items-center">
    <div class="sm:flex-auto">
        <h1 class="text-2xl font-bold text-gray-900">Users</h1>
        <p class="mt-1 text-sm text-gray-500">Manage user accounts</p>
    </div>
    <div class="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
        <a href="/admin/users/new"
            class="block rounded-md bg-blue-600 px-3 py-2 text-center text-sm font-semibold text-white shadow-sm hover:bg-blue-500">
            Add User
        </a>
    </div>
</div>

<div class="mt-8 flow-root">
    <div class="-mx-4 -my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
        <div class="inline-block min-w-full py-2 align-middle sm:px-6 lg:px-8">
            <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 sm:rounded-lg">
                <table class="min-w-full divide-y divide-gray-300">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-6">Username</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Role</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Status</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Last Login</th>
                            <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                                <span class="sr-only">Actions</span>
                            </th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 bg-white">
                        {{#each users}}
                        <tr>
                            <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-6">
                                {{this.username}}
                                {{#if this.display_name}}
                                <span class="text-gray-500 font-normal">({{this.display_name}})</span>
                                {{/if}}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm">
                                {{#if this.is_admin}}
                                <span class="inline-flex items-center rounded-full bg-purple-100 px-2.5 py-0.5 text-xs font-medium text-purple-800">
                                    {{this.role}}
                                </span>
                                {{else}}
                                <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-0.5 text-xs font-medium text-gray-800">
                                    {{this.role}}
                                </span>
                                {{/if}}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm">
                                {{#if this.is_active}}
                                <span class="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                                    Active
                                </span>
                                {{else}}
                                <span class="inline-flex items-center rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-medium text-red-800">
                                    {{this.status}}
                                </span>
                                {{/if}}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{{this.last_login}}</td>
                            <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                                <a href="/admin/users/{{this.username}}" class="text-blue-600 hover:text-blue-900 mr-3">Edit</a>
                                {{#unless this.is_current_user}}
                                <form action="/admin/users/{{this.username}}/delete" method="POST" class="inline" onsubmit="return confirm('Delete user {{this.username}}?')">
                                    <button type="submit" class="text-red-600 hover:text-red-900">Delete</button>
                                </form>
                                {{/unless}}
                            </td>
                        </tr>
                        {{/each}}
                        {{#unless users}}
                        <tr>
                            <td colspan="5" class="px-6 py-4 text-center text-sm text-gray-500">No users found</td>
                        </tr>
                        {{/unless}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
"#;

const USER_FORM_CONTENT: &str = r#"
<div class="mb-8">
    <h1 class="text-2xl font-bold text-gray-900">{{#if editing}}Edit User{{else}}Create User{{/if}}</h1>
    <p class="mt-1 text-sm text-gray-500">{{#if editing}}Update user settings{{else}}Add a new user account{{/if}}</p>
</div>

<div class="bg-white shadow-sm ring-1 ring-gray-900/5 sm:rounded-xl">
    <form action="{{form_action}}" method="POST" class="px-4 py-6 sm:p-8">
        <div class="grid max-w-2xl grid-cols-1 gap-x-6 gap-y-8 sm:grid-cols-6">
            <div class="sm:col-span-4">
                <label for="username" class="block text-sm font-medium leading-6 text-gray-900">Username</label>
                <div class="mt-2">
                    <input type="text" name="username" id="username" value="{{user.username}}" {{#if editing}}readonly{{/if}}
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6 {{#if editing}}bg-gray-50{{/if}}"
                        required>
                </div>
            </div>

            <div class="sm:col-span-4">
                <label for="password" class="block text-sm font-medium leading-6 text-gray-900">
                    Password {{#if editing}}<span class="text-gray-400 font-normal">(leave blank to keep current)</span>{{/if}}
                </label>
                <div class="mt-2">
                    <input type="password" name="password" id="password"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6"
                        {{#unless editing}}required{{/unless}}>
                </div>
            </div>

            <div class="sm:col-span-4">
                <label for="display_name" class="block text-sm font-medium leading-6 text-gray-900">Display Name</label>
                <div class="mt-2">
                    <input type="text" name="display_name" id="display_name" value="{{user.display_name}}"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">
                </div>
            </div>

            <div class="sm:col-span-3">
                <label for="role" class="block text-sm font-medium leading-6 text-gray-900">Role</label>
                <div class="mt-2">
                    <select id="role" name="role"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">
                        <option value="user" {{#if user.is_user}}selected{{/if}}>User</option>
                        <option value="admin" {{#if user.is_admin}}selected{{/if}}>Admin</option>
                        <option value="superadmin" {{#if user.is_superadmin}}selected{{/if}}>Super Admin</option>
                    </select>
                </div>
            </div>

            {{#if editing}}
            <div class="sm:col-span-3">
                <label for="status" class="block text-sm font-medium leading-6 text-gray-900">Status</label>
                <div class="mt-2">
                    <select id="status" name="status"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">
                        <option value="active" {{#if user.is_active}}selected{{/if}}>Active</option>
                        <option value="suspended" {{#if user.is_suspended}}selected{{/if}}>Suspended</option>
                    </select>
                </div>
            </div>
            {{/if}}
        </div>

        <div class="mt-6 flex items-center justify-end gap-x-6">
            <a href="/admin/users" class="text-sm font-semibold leading-6 text-gray-900">Cancel</a>
            <button type="submit"
                class="rounded-md bg-blue-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600">
                {{#if editing}}Save Changes{{else}}Create User{{/if}}
            </button>
        </div>
    </form>
</div>
"#;

const GROUPS_CONTENT: &str = r#"
<div class="sm:flex sm:items-center">
    <div class="sm:flex-auto">
        <h1 class="text-2xl font-bold text-gray-900">Groups</h1>
        <p class="mt-1 text-sm text-gray-500">Manage distribution lists and groups</p>
    </div>
    <div class="mt-4 sm:ml-16 sm:mt-0 sm:flex-none">
        <a href="/admin/groups/new"
            class="block rounded-md bg-blue-600 px-3 py-2 text-center text-sm font-semibold text-white shadow-sm hover:bg-blue-500">
            Add Group
        </a>
    </div>
</div>

<div class="mt-8 flow-root">
    <div class="-mx-4 -my-2 overflow-x-auto sm:-mx-6 lg:-mx-8">
        <div class="inline-block min-w-full py-2 align-middle sm:px-6 lg:px-8">
            <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 sm:rounded-lg">
                <table class="min-w-full divide-y divide-gray-300">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-6">Name</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Email</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Members</th>
                            <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">Owner</th>
                            <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                                <span class="sr-only">Actions</span>
                            </th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 bg-white">
                        {{#each groups}}
                        <tr>
                            <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-6">
                                {{this.name}}
                            </td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{{this.email}}</td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{{this.member_count}}</td>
                            <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{{this.owner}}</td>
                            <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                                <a href="/admin/groups/{{this.name}}" class="text-blue-600 hover:text-blue-900 mr-3">Edit</a>
                                <form action="/admin/groups/{{this.name}}/delete" method="POST" class="inline" onsubmit="return confirm('Delete group {{this.name}}?')">
                                    <button type="submit" class="text-red-600 hover:text-red-900">Delete</button>
                                </form>
                            </td>
                        </tr>
                        {{/each}}
                        {{#unless groups}}
                        <tr>
                            <td colspan="5" class="px-6 py-4 text-center text-sm text-gray-500">No groups found</td>
                        </tr>
                        {{/unless}}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
"#;

const GROUP_FORM_CONTENT: &str = r#"
<div class="mb-8">
    <h1 class="text-2xl font-bold text-gray-900">{{#if editing}}Edit Group{{else}}Create Group{{/if}}</h1>
    <p class="mt-1 text-sm text-gray-500">{{#if editing}}Manage group settings and members{{else}}Add a new group or distribution list{{/if}}</p>
</div>

<div class="bg-white shadow-sm ring-1 ring-gray-900/5 sm:rounded-xl">
    <form action="{{form_action}}" method="POST" class="px-4 py-6 sm:p-8">
        <div class="grid max-w-2xl grid-cols-1 gap-x-6 gap-y-8 sm:grid-cols-6">
            <div class="sm:col-span-4">
                <label for="name" class="block text-sm font-medium leading-6 text-gray-900">Group Name</label>
                <div class="mt-2">
                    <input type="text" name="name" id="name" value="{{group.name}}" {{#if editing}}readonly{{/if}}
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6 {{#if editing}}bg-gray-50{{/if}}"
                        required>
                </div>
            </div>

            <div class="sm:col-span-4">
                <label for="email" class="block text-sm font-medium leading-6 text-gray-900">Email Address</label>
                <div class="mt-2">
                    <input type="email" name="email" id="email" value="{{group.email}}"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6"
                        required>
                </div>
            </div>

            <div class="col-span-full">
                <label for="description" class="block text-sm font-medium leading-6 text-gray-900">Description</label>
                <div class="mt-2">
                    <textarea id="description" name="description" rows="3"
                        class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6">{{group.description}}</textarea>
                </div>
            </div>
        </div>

        <div class="mt-6 flex items-center justify-end gap-x-6">
            <a href="/admin/groups" class="text-sm font-semibold leading-6 text-gray-900">Cancel</a>
            <button type="submit"
                class="rounded-md bg-blue-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600">
                {{#if editing}}Save Changes{{else}}Create Group{{/if}}
            </button>
        </div>
    </form>
</div>

{{#if editing}}
<!-- Members Section -->
<div class="mt-8 bg-white shadow-sm ring-1 ring-gray-900/5 sm:rounded-xl">
    <div class="px-4 py-6 sm:p-8">
        <h2 class="text-lg font-medium text-gray-900 mb-4">Members ({{group.member_count}})</h2>
        
        <!-- Add Member Form -->
        <form action="/admin/groups/{{group.name}}/members" method="POST" class="flex gap-2 mb-4">
            <input type="text" name="username" placeholder="Username to add"
                class="block w-64 rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-blue-600 sm:text-sm sm:leading-6"
                required>
            <button type="submit"
                class="rounded-md bg-green-600 px-3 py-1.5 text-sm font-semibold text-white shadow-sm hover:bg-green-500">
                Add Member
            </button>
        </form>

        <!-- Members List -->
        <ul class="divide-y divide-gray-200">
            {{#each group.members}}
            <li class="flex items-center justify-between py-3">
                <span class="text-sm text-gray-900">{{this}}</span>
                <form action="/admin/groups/{{../group.name}}/members/{{this}}/remove" method="POST" class="inline">
                    <button type="submit" class="text-sm text-red-600 hover:text-red-900">Remove</button>
                </form>
            </li>
            {{/each}}
            {{#unless group.members}}
            <li class="py-3 text-sm text-gray-500">No members yet</li>
            {{/unless}}
        </ul>
    </div>
</div>
{{/if}}
"#;

// ============================================================================
// Handlers
// ============================================================================

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub struct UserForm {
    username: String,
    password: Option<String>,
    display_name: Option<String>,
    role: Option<String>,
    status: Option<String>,
}

#[derive(Deserialize)]
pub struct GroupForm {
    name: String,
    email: String,
    description: Option<String>,
}

#[derive(Deserialize)]
pub struct MemberForm {
    username: String,
}

#[derive(Serialize)]
struct UserView {
    username: String,
    display_name: String,
    role: String,
    status: String,
    is_admin: bool,
    is_active: bool,
    is_user: bool,
    is_superadmin: bool,
    is_suspended: bool,
    is_current_user: bool,
    last_login: String,
}

#[derive(Serialize)]
struct GroupView {
    name: String,
    email: String,
    description: String,
    owner: String,
    member_count: usize,
    members: Vec<String>,
}

/// Get session user from cookie
fn get_session_user(req: &HttpRequest) -> Option<String> {
    req.cookie("kiss_session").map(|c| c.value().to_string())
}

/// Login page
pub async fn login_page(data: web::Data<WebState>, req: HttpRequest) -> HttpResponse {
    // Already logged in?
    if get_session_user(&req).is_some() {
        return HttpResponse::Found()
            .append_header(("Location", "/admin"))
            .finish();
    }

    let body = data
        .hbs
        .render(
            "login",
            &json!({
                "version": env!("CARGO_PKG_VERSION"),
            }),
        )
        .unwrap_or_else(|e| format!("Template error: {}", e));

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}

/// Handle login
pub async fn login_submit(data: web::Data<WebState>, form: web::Form<LoginForm>) -> HttpResponse {
    match data
        .user_manager
        .authenticate(&form.username, &form.password, "web", "admin-web")
        .await
    {
        Ok(user) => {
            // Check if admin
            if !matches!(user.role, UserRole::Admin | UserRole::SuperAdmin) {
                let body = data
                    .hbs
                    .render(
                        "login",
                        &json!({
                            "version": env!("CARGO_PKG_VERSION"),
                            "error": "Admin access required",
                        }),
                    )
                    .unwrap_or_default();
                return HttpResponse::Ok()
                    .content_type("text/html; charset=utf-8")
                    .body(body);
            }

            // Set session cookie
            let cookie = Cookie::build("kiss_session", user.username.clone())
                .path("/")
                .http_only(true)
                .finish();

            HttpResponse::Found()
                .cookie(cookie)
                .append_header(("Location", "/admin"))
                .finish()
        }
        Err(_) => {
            let body = data
                .hbs
                .render(
                    "login",
                    &json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "error": "Invalid username or password",
                    }),
                )
                .unwrap_or_default();
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(body)
        }
    }
}

/// Logout
pub async fn logout() -> HttpResponse {
    let cookie = Cookie::build("kiss_session", "")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(0))
        .finish();

    HttpResponse::Found()
        .cookie(cookie)
        .append_header(("Location", "/admin/login"))
        .finish()
}

/// Dashboard
pub async fn dashboard(data: web::Data<WebState>, req: HttpRequest) -> HttpResponse {
    let username = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let users = data.user_manager.list_users().await;
    let groups = data.group_manager.list(Some(&username), true).await;
    let ldap_status = data.ldap_client.status();
    let sso_status = data.sso_manager.status();

    let active_users = users
        .iter()
        .filter(|u| format!("{:?}", u.status) == "Active")
        .count();
    let admins = users
        .iter()
        .filter(|u| matches!(u.role, UserRole::Admin | UserRole::SuperAdmin))
        .count();

    let content = data
        .hbs
        .render(
            "dashboard",
            &json!({
                "domain": data.domain,
                "stats": {
                    "users": users.len(),
                    "groups": groups.len(),
                    "active_users": active_users,
                    "admins": admins,
                },
                "ldap_enabled": ldap_status.enabled,
                "sso_enabled": sso_status.enabled,
                "sso_provider": sso_status.provider_name,
                "version": env!("CARGO_PKG_VERSION"),
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs,
        "Dashboard",
        &username,
        &content,
        true,
        false,
        false,
        None,
        None,
    )
}

/// Users list
pub async fn users_list(data: web::Data<WebState>, req: HttpRequest) -> HttpResponse {
    let username = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let users = data.user_manager.list_users().await;
    let user_views: Vec<UserView> = users
        .iter()
        .map(|u| UserView {
            username: u.username.clone(),
            display_name: u.settings.display_name.clone().unwrap_or_default(),
            role: format!("{:?}", u.role),
            status: format!("{:?}", u.status),
            is_admin: matches!(u.role, UserRole::Admin | UserRole::SuperAdmin),
            is_active: format!("{:?}", u.status) == "Active",
            is_user: matches!(u.role, UserRole::User),
            is_superadmin: matches!(u.role, UserRole::SuperAdmin),
            is_suspended: format!("{:?}", u.status) == "Suspended",
            is_current_user: u.username == username,
            last_login: u
                .last_login
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Never".to_string()),
        })
        .collect();

    let content = data
        .hbs
        .render(
            "users",
            &json!({
                "users": user_views,
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs, "Users", &username, &content, false, true, false, None, None,
    )
}

/// New user form
pub async fn user_new(data: web::Data<WebState>, req: HttpRequest) -> HttpResponse {
    let username = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let content = data
        .hbs
        .render(
            "user_form",
            &json!({
                "editing": false,
                "form_action": "/admin/users/new",
                "user": {},
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs, "New User", &username, &content, false, true, false, None, None,
    )
}

/// Create user
pub async fn user_create(
    data: web::Data<WebState>,
    req: HttpRequest,
    form: web::Form<UserForm>,
) -> HttpResponse {
    let username = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let role = match form.role.as_deref() {
        Some("admin") => Some(UserRole::Admin),
        Some("superadmin") => Some(UserRole::SuperAdmin),
        _ => Some(UserRole::User),
    };

    let password = form.password.as_deref().unwrap_or("");

    match data
        .user_manager
        .create_user(&form.username, password, role)
        .await
    {
        Ok(_) => {
            if let Some(name) = &form.display_name {
                if !name.is_empty() {
                    let _ = data
                        .user_manager
                        .update_user(&form.username, |u| {
                            u.settings.display_name = Some(name.clone());
                        })
                        .await;
                }
            }
            HttpResponse::Found()
                .append_header(("Location", "/admin/users?success=User+created"))
                .finish()
        }
        Err(e) => {
            let content = data
                .hbs
                .render(
                    "user_form",
                    &json!({
                        "editing": false,
                        "form_action": "/admin/users/new",
                        "user": {
                            "username": form.username,
                            "display_name": form.display_name,
                        },
                    }),
                )
                .unwrap_or_default();
            render_page(
                &data.hbs,
                "New User",
                &username,
                &content,
                false,
                true,
                false,
                None,
                Some(&format!("{:?}", e)),
            )
        }
    }
}

/// Edit user form
pub async fn user_edit(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let session_user = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let target_username = path.into_inner();

    let user = match data.user_manager.get_user(&target_username).await {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/users?error=User+not+found"))
                .finish();
        }
    };

    let content = data
        .hbs
        .render(
            "user_form",
            &json!({
                "editing": true,
                "form_action": format!("/admin/users/{}", target_username),
                "user": {
                    "username": user.username,
                    "display_name": user.settings.display_name.clone().unwrap_or_default(),
                    "is_user": matches!(user.role, UserRole::User),
                    "is_admin": matches!(user.role, UserRole::Admin),
                    "is_superadmin": matches!(user.role, UserRole::SuperAdmin),
                    "is_active": format!("{:?}", user.status) == "Active",
                    "is_suspended": format!("{:?}", user.status) == "Suspended",
                },
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs,
        "Edit User",
        &session_user,
        &content,
        false,
        true,
        false,
        None,
        None,
    )
}

/// Update user
pub async fn user_update(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
    form: web::Form<UserForm>,
) -> HttpResponse {
    let session_user = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let target_username = path.into_inner();

    // Get current user for actor
    let actor = match data.user_manager.get_user(&session_user).await {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    // Update password if provided
    if let Some(password) = &form.password {
        if !password.is_empty() {
            let _ = data
                .user_manager
                .admin_reset_password(&target_username, password, &actor, false)
                .await;
        }
    }

    // Update display name
    if let Some(name) = &form.display_name {
        let _ = data
            .user_manager
            .update_user(&target_username, |u| {
                u.settings.display_name = if name.is_empty() {
                    None
                } else {
                    Some(name.clone())
                };
            })
            .await;
    }

    // Update role
    if let Some(role_str) = &form.role {
        let role = match role_str.as_str() {
            "admin" => UserRole::Admin,
            "superadmin" => UserRole::SuperAdmin,
            _ => UserRole::User,
        };
        let _ = data
            .user_manager
            .set_role(&target_username, role, &actor)
            .await;
    }

    // Update status
    if let Some(status_str) = &form.status {
        use crate::users::AccountStatus;
        let status = match status_str.as_str() {
            "suspended" => AccountStatus::Suspended,
            _ => AccountStatus::Active,
        };
        let _ = data
            .user_manager
            .set_status(&target_username, status, &actor)
            .await;
    }

    HttpResponse::Found()
        .append_header(("Location", "/admin/users?success=User+updated"))
        .finish()
}

/// Delete user
pub async fn user_delete(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let session_user = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let target_username = path.into_inner();

    let actor = match data.user_manager.get_user(&session_user).await {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    match data
        .user_manager
        .delete_user(&target_username, &actor)
        .await
    {
        Ok(_) => HttpResponse::Found()
            .append_header(("Location", "/admin/users?success=User+deleted"))
            .finish(),
        Err(e) => HttpResponse::Found()
            .append_header(("Location", format!("/admin/users?error={:?}", e)))
            .finish(),
    }
}

/// Groups list
pub async fn groups_list(data: web::Data<WebState>, req: HttpRequest) -> HttpResponse {
    let username = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let groups = data.group_manager.list(Some(&username), true).await;
    let group_views: Vec<GroupView> = groups
        .iter()
        .map(|g| GroupView {
            name: g.name.clone(),
            email: g.email.clone(),
            description: g.description.clone(),
            owner: g.owner.clone(),
            member_count: g.members.len(),
            members: g.members.iter().cloned().collect(),
        })
        .collect();

    let content = data
        .hbs
        .render(
            "groups",
            &json!({
                "groups": group_views,
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs, "Groups", &username, &content, false, false, true, None, None,
    )
}

/// New group form
pub async fn group_new(data: web::Data<WebState>, req: HttpRequest) -> HttpResponse {
    let username = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let content = data
        .hbs
        .render(
            "group_form",
            &json!({
                "editing": false,
                "form_action": "/admin/groups/new",
                "group": {},
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs,
        "New Group",
        &username,
        &content,
        false,
        false,
        true,
        None,
        None,
    )
}

/// Create group
pub async fn group_create(
    data: web::Data<WebState>,
    req: HttpRequest,
    form: web::Form<GroupForm>,
) -> HttpResponse {
    let username = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    match data
        .group_manager
        .create(&form.name, &form.email, &username)
        .await
    {
        Ok(mut group) => {
            if let Some(desc) = &form.description {
                group.description = desc.clone();
                let _ = data.group_manager.save().await;
            }
            HttpResponse::Found()
                .append_header(("Location", "/admin/groups?success=Group+created"))
                .finish()
        }
        Err(e) => {
            let content = data
                .hbs
                .render(
                    "group_form",
                    &json!({
                        "editing": false,
                        "form_action": "/admin/groups/new",
                        "group": {
                            "name": form.name,
                            "email": form.email,
                            "description": form.description,
                        },
                    }),
                )
                .unwrap_or_default();
            render_page(
                &data.hbs,
                "New Group",
                &username,
                &content,
                false,
                false,
                true,
                None,
                Some(&format!("{:?}", e)),
            )
        }
    }
}

/// Edit group form
pub async fn group_edit(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let username = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let group_name = path.into_inner();

    let group = match data.group_manager.get(&group_name).await {
        Some(g) => g,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/groups?error=Group+not+found"))
                .finish();
        }
    };

    let members: Vec<String> = group.members.iter().cloned().collect();

    let content = data
        .hbs
        .render(
            "group_form",
            &json!({
                "editing": true,
                "form_action": format!("/admin/groups/{}", group_name),
                "group": {
                    "name": group.name,
                    "email": group.email,
                    "description": group.description,
                    "owner": group.owner,
                    "member_count": members.len(),
                    "members": members,
                },
            }),
        )
        .unwrap_or_default();

    render_page(
        &data.hbs,
        "Edit Group",
        &username,
        &content,
        false,
        false,
        true,
        None,
        None,
    )
}

/// Update group
pub async fn group_update(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
    form: web::Form<GroupForm>,
) -> HttpResponse {
    let _username = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let group_name = path.into_inner();

    // Update group
    if let Some(mut group) = data.group_manager.get(&group_name).await {
        group.email = form.email.clone();
        group.description = form.description.clone().unwrap_or_default();
        let _ = data.group_manager.save().await;
    }

    HttpResponse::Found()
        .append_header((
            "Location",
            format!("/admin/groups/{}?success=Group+updated", group_name),
        ))
        .finish()
}

/// Delete group
pub async fn group_delete(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let username = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let group_name = path.into_inner();

    match data.group_manager.delete(&group_name, &username).await {
        Ok(_) => HttpResponse::Found()
            .append_header(("Location", "/admin/groups?success=Group+deleted"))
            .finish(),
        Err(e) => HttpResponse::Found()
            .append_header(("Location", format!("/admin/groups?error={:?}", e)))
            .finish(),
    }
}

/// Add group member
pub async fn group_add_member(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<String>,
    form: web::Form<MemberForm>,
) -> HttpResponse {
    let session_user = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let group_name = path.into_inner();

    match data
        .group_manager
        .add_member(&group_name, &form.username, &session_user)
        .await
    {
        Ok(_) => HttpResponse::Found()
            .append_header((
                "Location",
                format!("/admin/groups/{}?success=Member+added", group_name),
            ))
            .finish(),
        Err(e) => HttpResponse::Found()
            .append_header((
                "Location",
                format!("/admin/groups/{}?error={:?}", group_name, e),
            ))
            .finish(),
    }
}

/// Remove group member
pub async fn group_remove_member(
    data: web::Data<WebState>,
    req: HttpRequest,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let session_user = match get_session_user(&req) {
        Some(u) => u,
        None => {
            return HttpResponse::Found()
                .append_header(("Location", "/admin/login"))
                .finish();
        }
    };

    let (group_name, member) = path.into_inner();

    match data
        .group_manager
        .remove_member(&group_name, &member, &session_user)
        .await
    {
        Ok(_) => HttpResponse::Found()
            .append_header((
                "Location",
                format!("/admin/groups/{}?success=Member+removed", group_name),
            ))
            .finish(),
        Err(e) => HttpResponse::Found()
            .append_header((
                "Location",
                format!("/admin/groups/{}?error={:?}", group_name, e),
            ))
            .finish(),
    }
}

// ============================================================================
// Helpers
// ============================================================================

#[allow(clippy::too_many_arguments)]
fn render_page(
    hbs: &Handlebars,
    title: &str,
    username: &str,
    content: &str,
    nav_dashboard: bool,
    nav_users: bool,
    nav_groups: bool,
    flash_success: Option<&str>,
    flash_error: Option<&str>,
) -> HttpResponse {
    let body = hbs
        .render(
            "base",
            &json!({
                "title": title,
                "username": username,
                "content": content,
                "nav_dashboard": nav_dashboard,
                "nav_users": nav_users,
                "nav_groups": nav_groups,
                "flash_success": flash_success,
                "flash_error": flash_error,
            }),
        )
        .unwrap_or_else(|e| format!("Template error: {}", e));

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}

/// Create Handlebars instance with templates
pub fn create_handlebars() -> Handlebars<'static> {
    let mut hbs = Handlebars::new();
    hbs.set_strict_mode(false);

    hbs.register_template_string("base", BASE_TEMPLATE).unwrap();
    hbs.register_template_string("login", LOGIN_TEMPLATE)
        .unwrap();
    hbs.register_template_string("dashboard", DASHBOARD_CONTENT)
        .unwrap();
    hbs.register_template_string("users", USERS_CONTENT)
        .unwrap();
    hbs.register_template_string("user_form", USER_FORM_CONTENT)
        .unwrap();
    hbs.register_template_string("groups", GROUPS_CONTENT)
        .unwrap();
    hbs.register_template_string("group_form", GROUP_FORM_CONTENT)
        .unwrap();

    hbs
}

/// Configure routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .route("/login", web::get().to(login_page))
            .route("/login", web::post().to(login_submit))
            .route("/logout", web::get().to(logout))
            .route("", web::get().to(dashboard))
            .route("/", web::get().to(dashboard))
            .route("/users", web::get().to(users_list))
            .route("/users/new", web::get().to(user_new))
            .route("/users/new", web::post().to(user_create))
            .route("/users/{username}", web::get().to(user_edit))
            .route("/users/{username}", web::post().to(user_update))
            .route("/users/{username}/delete", web::post().to(user_delete))
            .route("/groups", web::get().to(groups_list))
            .route("/groups/new", web::get().to(group_new))
            .route("/groups/new", web::post().to(group_create))
            .route("/groups/{name}", web::get().to(group_edit))
            .route("/groups/{name}", web::post().to(group_update))
            .route("/groups/{name}/delete", web::post().to(group_delete))
            .route("/groups/{name}/members", web::post().to(group_add_member))
            .route(
                "/groups/{name}/members/{member}/remove",
                web::post().to(group_remove_member),
            ),
    );
}

/// Start the web admin server
pub async fn run_web_server(
    user_manager: Arc<UserManager>,
    group_manager: Arc<GroupManager>,
    ldap_client: Arc<LdapClient>,
    sso_manager: Arc<SsoManager>,
    domain: String,
    config: WebAdminConfig,
) -> std::io::Result<()> {
    use actix_web::{App, HttpServer};

    if !config.enabled {
        tracing::info!("Web admin disabled (set KISS_MAIL_WEB_ENABLED=true to enable)");
        return Ok(());
    }

    let addr = format!("{}:{}", config.bind_address, config.port);

    let web_state = web::Data::new(WebState {
        user_manager,
        group_manager,
        ldap_client,
        sso_manager,
        hbs: create_handlebars(),
        domain,
    });

    tracing::info!("Web admin listening on http://{}", addr);

    HttpServer::new(move || {
        App::new()
            .app_data(web_state.clone())
            .configure(configure_routes)
            .route(
                "/",
                web::get().to(|| async {
                    HttpResponse::Found()
                        .append_header(("Location", "/admin"))
                        .finish()
                }),
            )
    })
    .bind(&addr)?
    .run()
    .await
}

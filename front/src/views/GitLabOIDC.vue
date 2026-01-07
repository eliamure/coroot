<template>
    <div>
        <v-alert v-if="error" color="red" icon="mdi-alert-octagon-outline" outlined text class="mt-2">
            {{ error }}
        </v-alert>
        <v-alert v-if="readonly" color="primary" outlined text>
            GitLab OIDC is configured through the config and cannot be modified via the UI.
        </v-alert>
        <v-simple-table v-if="status !== 403" dense class="params">
            <tbody>
                <tr>
                    <td class="font-weight-medium text-no-wrap">Status</td>
                    <td>
                        <div v-if="enabled">
                            <v-icon color="success" class="mr-1" size="20">mdi-check-circle</v-icon>
                            Enabled
                        </div>
                        <div v-else>Disabled</div>
                    </td>
                </tr>
                <tr>
                    <td class="font-weight-medium text-no-wrap">GitLab URL:</td>
                    <td>
                        <v-text-field
                            v-model="url"
                            :disabled="loading || readonly"
                            placeholder="https://gitlab.example.com"
                            outlined
                            dense
                            hide-details
                            class="gitlab-field"
                        />
                    </td>
                </tr>
                <tr>
                    <td class="font-weight-medium text-no-wrap">Client ID:</td>
                    <td>
                        <v-text-field
                            v-model="client_id"
                            :disabled="loading || readonly"
                            placeholder="Application ID from GitLab"
                            outlined
                            dense
                            hide-details
                            class="gitlab-field"
                        />
                    </td>
                </tr>
                <tr>
                    <td class="font-weight-medium text-no-wrap">Client Secret:</td>
                    <td>
                        <v-text-field
                            v-model="client_secret"
                            :disabled="loading || readonly"
                            :placeholder="enabled ? '********' : 'Application Secret from GitLab'"
                            type="password"
                            outlined
                            dense
                            hide-details
                            class="gitlab-field"
                        />
                    </td>
                </tr>
                <tr>
                    <td class="font-weight-medium text-no-wrap">Redirect URI (Callback URL):</td>
                    <td>{{ redirect_uri }} <CopyButton :text="redirect_uri" /></td>
                </tr>
                <tr>
                    <td class="font-weight-medium text-no-wrap">Scopes:</td>
                    <td><code>openid profile email</code></td>
                </tr>
                <tr>
                    <td class="font-weight-medium text-no-wrap">Default role:</td>
                    <td>
                        <v-select
                            v-model="default_role"
                            :items="roles"
                            :disabled="readonly"
                            outlined
                            dense
                            :menu-props="{ offsetY: true }"
                            :rules="[$validators.notEmpty]"
                            hide-details
                            class="roles"
                        />
                    </td>
                </tr>
            </tbody>
        </v-simple-table>

        <v-alert v-if="status !== 403" color="info" outlined text class="mt-4">
            <h4>GitLab Application Setup</h4>
            <ol class="mt-2 mb-0">
                <li>Go to your GitLab instance: <b>Admin Area → Applications</b> (for instance-wide) or <b>User Settings → Applications</b> (for user-owned)</li>
                <li>Create a new application with the following settings:
                    <ul>
                        <li><b>Name:</b> Coroot</li>
                        <li><b>Redirect URI:</b> <code>{{ redirect_uri }}</code></li>
                        <li><b>Confidential:</b> Yes (checked)</li>
                        <li><b>Scopes:</b> openid, profile, email</li>
                    </ul>
                </li>
                <li>Copy the <b>Application ID</b> and <b>Secret</b> and paste them above</li>
            </ol>
        </v-alert>

        <div v-if="status !== 403" class="d-flex mt-2" style="gap: 8px">
            <v-btn color="primary" small :disabled="loading || readonly || !url || !client_id" @click="save">
                Save <template v-if="!enabled">and Enable</template>
            </v-btn>
            <v-btn v-if="enabled" color="error" small :disabled="loading || readonly" @click="disable">Disable</v-btn>
            <v-btn v-if="enabled" color="secondary" small :disabled="loading" @click="testLogin">
                Test Login
            </v-btn>
        </div>
    </div>
</template>

<script>
import CopyButton from '@/components/CopyButton.vue';

export default {
    components: { CopyButton },
    computed: {
        redirect_uri() {
            return location.origin + this.$coroot.base_path + 'sso/gitlab/callback';
        },
    },

    data() {
        return {
            readonly: false,
            loading: false,
            error: '',
            status: undefined,
            enabled: false,
            url: '',
            client_id: '',
            client_secret: '',
            default_role: 'Viewer',
            roles: [],
        };
    },

    mounted() {
        this.$events.watch(this, this.get, 'roles');
        this.get();
    },

    methods: {
        get() {
            this.loading = true;
            this.error = '';
            this.status = undefined;
            this.$api.gitlabOidc(null, (data, error, status) => {
                this.loading = false;
                if (error) {
                    this.error = error;
                    this.status = status;
                    return;
                }
                this.readonly = data.readonly;
                this.enabled = data.enabled;
                this.url = data.url || '';
                this.client_id = data.client_id || '';
                this.default_role = data.default_role || 'Viewer';
                this.roles = data.roles || [];
            });
        },
        save() {
            this.loading = true;
            this.error = '';
            this.status = undefined;
            const form = {
                action: 'save',
                url: this.url,
                client_id: this.client_id,
                client_secret: this.client_secret,
                default_role: this.default_role,
            };
            this.$api.gitlabOidc(form, (data, error, status) => {
                this.loading = false;
                if (error) {
                    this.error = error;
                    this.status = status;
                    return;
                }
                this.client_secret = '';
                this.get();
            });
        },
        disable() {
            this.loading = true;
            this.error = '';
            this.status = undefined;
            const form = {
                action: 'disable',
            };
            this.$api.gitlabOidc(form, (data, error, status) => {
                this.loading = false;
                if (error) {
                    this.error = error;
                    this.status = status;
                    return;
                }
                this.get();
            });
        },
        testLogin() {
            window.location.href = this.$coroot.base_path + 'sso/gitlab/login';
        },
    },
};
</script>

<style scoped>
.params:deep(td) {
    padding: 4px 16px !important;
}
.roles {
    max-width: 20ch;
}
.roles:deep(.v-input__slot) {
    min-height: initial !important;
    height: 2rem !important;
    padding: 0 8px !important;
}
.roles:deep(.v-input__append-inner) {
    margin-top: 4px !important;
}
.gitlab-field {
    max-width: 40ch;
}
.gitlab-field:deep(.v-input__slot) {
    min-height: initial !important;
    height: 2rem !important;
    padding: 0 8px !important;
}
</style>

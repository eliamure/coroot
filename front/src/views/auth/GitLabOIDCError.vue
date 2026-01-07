<template>
    <v-alert color="red" elevation="2" border="left" colored-border class="mx-auto mt-5 pr-8" min-width="60%">
        <a href="https://docs.coroot.com/configuration/authentication#gitlab-oidc" target="_blank" class="doc-link">
            <v-icon>mdi-information-outline</v-icon>
        </a>
        <div v-if="error === 'invalid_state'">
            <div>The authentication session has expired or is invalid.</div>
            <div>Please try logging in again.</div>
        </div>
        <div v-else-if="error === 'missing_code'">
            <div>Authorization code was not provided by GitLab.</div>
            <div>Please try logging in again.</div>
        </div>
        <div v-else-if="error === 'token_exchange'">
            <div>Failed to exchange authorization code for access token.</div>
            <div>Please check that the Client ID and Client Secret are correctly configured.</div>
        </div>
        <div v-else-if="error === 'user_info'">
            <div>Failed to retrieve user information from GitLab.</div>
            <div>Please ensure the application has the required scopes: <b>openid</b>, <b>profile</b>, <b>email</b>.</div>
        </div>
        <div v-else-if="error === 'user_creation'">
            <div>Failed to create or update user account.</div>
            <div>Please contact your Coroot administrator.</div>
        </div>
        <div v-else>
            <div>Authentication using GitLab OIDC was unsuccessful.</div>
            <div v-if="error">Error: {{ error }}</div>
        </div>
        <div class="mt-2 d-flex" style="gap: 8px">
            <v-btn :to="{ name: 'index' }" color="primary">Refresh</v-btn>
            <v-btn :to="{ name: 'login' }" color="warning">Login as Admin</v-btn>
        </div>
    </v-alert>
</template>

<script>
export default {
    computed: {
        error() {
            return this.$route.query.error;
        },
    },
};
</script>

<style scoped>
.doc-link {
    position: absolute;
    right: 8px;
    top: 8px;
}
</style>

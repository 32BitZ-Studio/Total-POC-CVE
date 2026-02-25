FROM mcr.microsoft.com/devcontainers/typescript-node:1-20-bookworm

ARG USERNAME=node
ARG WORKSPACE_FOLDER=/workspaces

RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
    && mkdir /commandhistory \
    && touch /commandhistory/.bash_history \
    && chown -R $USERNAME /commandhistory \
    && echo "$SNIPPET" >> "/home/$USERNAME/.bashrc"

RUN mkdir -p $WORKSPACE_FOLDER/node_modules && \
    chown -R $USERNAME $WORKSPACE_FOLDER/node_modules

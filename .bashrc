# .bashrc

# Source global definitions
if [ -f /etc/bashrc ]; then
	. /etc/bashrc
fi

# User specific environment
if ! [[ "$PATH" =~ "$HOME/.local/bin:$HOME/bin:" ]]
then
    PATH="$HOME/.local/bin:$HOME/bin:$PATH"
fi
export PATH

# Uncomment the following line if you don't like systemctl's auto-paging feature:
# export SYSTEMD_PAGER=

# User specific aliases and functions
alias pip='pip3 --proxy http://rhsm-proxy.gsd.esrl.noaa.gov:3128'
alias rm-pycache='find . -type d -name  "__pycache__" -exec rm -r {} +'

source /opt/ssop/venv/bin/activate
VIRTUAL_ENV=/opt/ssop/venv
SSOP_DEPLOY_ENV='Development'

#!/usr/bin/env python3
# 6/1/21 GitStoph
# For looking up users, groups, etc. 
# v0.1 - initial build.
# Noteworthy URLs from research:
#
########################################################################################

import sys, os
import getpass
from dotenv import load_dotenv
from ldap3 import Server, Connection, SUBTREE, LEVEL, ALL_ATTRIBUTES, MODIFY_REPLACE, NTLM, ALL_OPERATIONAL_ATTRIBUTES
from datetime import datetime, timedelta
import json
from rich.console import Console
from rich.table import Table
from rich import pretty

pretty.install()
console = Console()
load_dotenv(os.path.join('/opt/ldap3scripts', '.env'))

ldapserver = os.environ.get('LDAP_HOST')
searchou = os.environ.get('SEARCH_OU')
adminsearchou = os.environ.get('ADMIN_SEARCH_OU')

def connect_to_ldap():
    """Creates the server object using default ldaps. Next it attempts
    to connect to the LDAP server using the username of the currently
    signed in user. Next it prompts for the password of the signed in
    user. It then connects using NTLM auth, and prints that the login
    was successful, or prints the error if it wasn't."""
    try:
        server = Server(ldapserver, port=636, use_ssl=True, get_info='ALL')
        connection = Connection(server, user='domainshortname\\{0}'.format(getpass.getuser()),
                    password=getpass.getpass(prompt='Password: ', stream=None),
                    authentication=NTLM,
                    fast_decoder=True, auto_bind=True, auto_referrals=True,
                    check_names=False, read_only=False, lazy=False,
                    raise_exceptions=False)
        console.print("[I] Info: ", "Login successful.", style='green')
        return connection
    except:
        console.print("[!] Error: ", sys.exc_info()[1], style='bold red')
        exit()


def user_timestamp(timestamp):
    """This converts the user timestamp from Microsoft time to a easier
    to read datetime object. If there's an overflow error, the user
    never expires, and it returns that info."""
    try:
        translatedtime = datetime(1601, 1, 1)+timedelta(seconds=int(timestamp)/10000000)
        return translatedtime.strftime('%Y-%m-%d %H:%M:%S')
    except OverflowError:
        return 'Never Expires'


def pw_reset_timestamp(timestamp):
    """This takes the translated time, puts it in a datetime object,
    then returns when the user's password should expire in the future.
    This assumes a 90 day password reset standard."""
    try:
        translatedtime = datetime(1601, 1, 1)+timedelta(seconds=int(timestamp)/10000000)
        resetTime = translatedtime+timedelta(days=90)
        return resetTime.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return 'Error Calculating.'


def ldap_user_info(connection, outosearch, searchstring):
    """First it creates a blank list. Next it attempts to search
    outosearch for the sAMAccountname (searchstring). Next it iterates
    through the returned list. If a dict of the json.loads object of
    entry_to_json is NOT in the results list, it appends it to the list.
    If results don't equal zero, it prints out that the searchstring
    was found in the outosearch. If not, it prints an error saying that
    the searchstring was not found in the outosearch."""
    results = []
    if connection.search(outosearch, '(&(objectclass=person)(sAMAccountname=*{0}))'.format(searchstring), attributes=ALL_ATTRIBUTES) == True:
        for entry in connection.entries:
            if json.loads(entry.entry_to_json()) not in results:
                results.append(json.loads(entry.entry_to_json()))
    if len(results) != 0:
        console.print("[I] Info:", searchstring, "was located in {0}!".format(outosearch), style='green')
        return results
    else:
        console.print("[!] Error:", searchstring, "was not located in {0}!".format(outosearch), style='bold red')
        return False


def search_for_groups(connection, searchstring):
    """This takes the connection object, and uses it to search for the
    OU=Groups in the searchou. Next it creates a blank groupresults list. 
    It takes the sorted list of entries returned and checks to see if the
    searchstring is in the distinguishedName of each entry. If the group
    results is creater than 0, it returns it. If not, it prints that the
    searchstring was not located in the searchou."""
    connection.search(
        search_base = 'OU=Groups,{0}'.format(searchou),
        search_filter = '(objectClass=group)',
        attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
    groupresults = []
    for e in sorted(connection.entries):
        try:
            if searchstring in e.entry_attributes_as_dict['distinguishedName'][0]:
                groupresults.append(e.entry_attributes_as_dict)
        except:
            pass
    if len(groupresults) > 0:
        return groupresults
    else:
        console.print("[!] Error:", searchstring, "was not located in {0} groups!".format(searchou), style='bold red')
        return False


def search_all_ous(connection, searchstring):
    """This takes the connection object, and attempts to use the
    ldap_user_info function to search both the searchou, and
    adminsearchou for the searchstring that was provided. If there are
    results and results2, return both in a combined list. If not, return
    whichever had results."""
    results = ldap_user_info(connection, searchou, searchstring)
    results2 = ldap_user_info(connection, adminsearchou, searchstring)
    if results != False:
        if results2 == False:
            return results
        else:
            return results + results2
    if results == False:
        if results2 != False:
            return results2


def dictify_results(listofusers):
    """Here we're creating a custom dict of every user in listofusers.
    We define which keys are important to us, create the dict object and
    a blank list of results. Then we iterate for every user in the
    listofusers to see if every key we care about is there. If not, it
    adds the key, and gives it the value of 'Missing.' It maps the dn
    key to the user dn key, then creates a blank memberof string. It then 
    tries to iterate through every item in the memberOf, and adds it to
    the string with a newline so it will print nice down the road. Lastly
    it tries to set the timestamps to an easier to read datetime object."""
    listofkeys = ['cn', 'company', 'department', 'description', 'distinguishedName',
                'mail', 'manager', 'memberOf']
    userdict = {}
    userresults = []
    for user in listofusers:
        for key in listofkeys:
            try:
                userdict[key] = user['attributes'][key][0]
            except:
                userdict[key] = 'Missing.'
        userdict['dn'] = user['dn']
        memberof = ""
        try:
            for item in user['attributes']['memberOf']:
                memberof += item+' \n'
        except:
            console.print("[!] Error: ", sys.exc_info()[1], style='bold red')
            pass
        userdict['memberOf'] = memberof
        try:
            userdict['lastLogonTimestamp'] = user_timestamp(user['attributes']['lastLogonTimestamp'][0])
            userdict['pwdLastSet'] = pw_reset_timestamp(user['attributes']['pwdLastSet'][0])
        except:
            userdict['lastLogonTimestamp'] = "Error calculating."
            userdict['pwdLastSet'] = "Error calculating."
        userresults.append(userdict.copy())
    return userresults


def pretty_output(listofusers):
    """Creates a rich Table object. Adds the columns. Creates a dntable
    object the same way, and adds those two columns. Next it iterates
    through the list of users to to add rows. It additionally adds rows
    to the dntaable. If there's an error, it passes. Lastly it prints the
    table out in green, and the dntable regular."""
    table = Table(show_header=True, header_style="cyan", show_lines=True)
    table.add_column("cn", justify="right")
    table.add_column("company", justify="right")
    table.add_column("department", justify="right")
    table.add_column("description", justify="right")
    table.add_column("mail", justify="right")
    table.add_column("lastLogonTimestamp", justify="right")
    table.add_column("passwordExpires", justify="right")
    dntable = Table(show_header=True, header_style="cyan", show_lines=True)
    dntable.add_column("key", justify="right")
    dntable.add_column("result", justify="right")
    for u in listofusers:
        table.add_row(u['cn'], u['company'], u['department'], u['description'], u['mail'],
                    u['lastLogonTimestamp'], u['pwdLastSet'])
        dntable.add_row("[green]manager[/green]", u['manager'])
        try:
            dntable.add_row("[green]memberOf[/green]", u['memberOf'])
        except:
            console.print("[!] Error: ", sys.exc_info()[1], style='bold red')
            pass
        dntable.add_row("[green]dn[/green]", u['dn'])
    console.print(table, style='green')
    console.print(dntable)


def dictify_group_results(listofgroups):
    """This creates a list of dicts from the group objects the same way
    it did for the users above, just with less keys. """
    listofkeys = ['cn', 'distinguishedName', 'memberOf', 'member', 'managedBy', 'mail']
    groupresults = []
    groupdict = {}
    for e in listofgroups:
        for key in listofkeys:
            try:
                groupdict[key] = e[key]
            except:
                groupdict[key] = 'NA'
        groupresults.append(groupdict.copy())
    return groupresults


def pretty_group_output(listofgroups):
    """Prints out the group search results with rich's console. For each
    item in the list of groups, it creates the template below, then
    prints it out."""
    console.print(" --- GROUP SEARCH RESULTS ---", style='bold red')
    for e in listofgroups:
        template = """[cyan]-----------------------------------------------------------[/cyan]
    [yellow]---- Group ----[/yellow] [green]{cn}[/green]
    [cyan]-----------------------------------------------------------[/cyan]
    [yellow]-- distinguishedName --[/yellow] [green]{distinguishedName}[/green]
    [cyan]-----------------------------------------------------------[/cyan]
    [yellow]-- memberOf --[/yellow] [green]{memberOf}[/green]
    [cyan]-----------------------------------------------------------[/cyan]
    [yellow]-- member --[/yellow] [green]{member}[/green]
    [cyan]-----------------------------------------------------------[/cyan]
    [yellow]-- managedBy --[/yellow] [green]{managedBy}[/green]
    [cyan]-----------------------------------------------------------[/cyan]
    [yellow]-- mail --[/yellow] [green]{mail}[/green]
    """.format(cn=e['cn'], distinguishedName=e['distinguishedName'],
            memberOf=e['memberOf'], member=e['member'], managedBy=e['managedBy'],
            mail=e['mail'])
        console.print(template)


def main():
    """Tries to connect to ldap, populates the users by searching both
    OUs as mentioned above. If an underscore is in the arg, it'll search
    groups. If users are found, it puts them in dicts and prints them
    out. If groups isn't False, it prints those results out."""
    try:
        conn = connect_to_ldap()
        users = search_all_ous(conn, sys.argv[1])
        if '_' in sys.argv[1]:
            groups = search_for_groups(conn, sys.argv[1])
        else:
            groups = False
        conn.unbind()
        if users != False:
            dictusers = dictify_results(users)
            pretty_output(dictusers)
        if groups != False:
            dictgroups = dictify_group_results(groups)
            pretty_group_output(dictgroups)
    except:
        console.print("[!] Error: ", sys.exc_info()[1], style='bold red')
        exit()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[!!!] Ctrl + C Detected!", style='bold red')
        console.print("[XXX] Exiting script now..", style='bold red')
        exit()

import discord
from discord.ext import tasks, commands
import string
import json
import requests
import sys
import os
import traceback
import tarfile
import pickle
import help_info
import time as tm
from dateutil.parser import parse
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from datetime import *
from config_vars import *
sys.path.append("..")

################################ DATA STRUCTURES ###############################
chall_aliases = {
    "crypto": ["crypto", "cryptography", "aes", "rsa", "encryption", "encoding", "cipher", "ciphers"],
    "forensics": ["forensics", "stego", "steganography", "memory analysis", "wireshark"],
    "misc": ["misc", "other", "miscellaneous", "trivia", "random", "warmup"],
    "osint": ["osint", "open source intelligence", "google", "internet"],
    "web exploitation": ["web", "web-exploitation", "web exploitation", "webexp"],
    "pwn": ["pwn", "pwning", "binary exploitation", "binary-exploitation", "exploitation", "kernel exploitation", "kernel", "pwn / rev"],
    "reversing": ["reverse", "reversing", "re", "reverse engineering", "reverse-engineering", "rev", "rev / pwn"],
    "tryhackme": ["htb", "hackthebox", "hack the box", "try hack me", "tryhackme"]
}
keys = pickle.load(open("passwords.p", "rb"))

#################################### METHODS ###################################
# verifies that the command called exists within
def in_ctf_channel():
    async def tocheck(ctx):
        # A check for ctf context specific commands
        if not (str(ctx.channel.type) == "private") and \
           client[str(ctx.guild.name).replace(' ', '-')]['ctfs'].find_one({'name': str(ctx.message.channel)}):
            return True
        else:
            await ctx.send("You must be in a created ctf channel to use ctf commands!")
            return False

    return commands.check(tocheck)

# verifies that the command is called in-server and not over DM
def in_channel():
    async def tocheck(ctx):
        # A check for ctf context specific commands
        if not str(ctx.channel.type) == "private":
            return True
        else:
            await ctx.send("This command is not available over DM!")
            return False

    return commands.check(tocheck)

# Get correct place suffix
def place(pl):
    if pl == 0:
        pl = "N/A"
    elif pl >= 11 and pl <= 13:
        pl = "{}th".format(pl)
    elif pl % 10 == 1:
        pl = "{}st".format(pl)
    elif pl % 10 == 2:
        pl = "{}nd".format(pl)
    elif pl % 10 == 3:
        pl = "{}rd".format(pl)
    else:
        pl = "{}th".format(pl)
    return pl

# NOTE: currently only used by get_info()
def check_aliases(guild, creds, channel_name):
    fingerprints = ["Powered by CTFd", "meta name=\"rctf-config\"", "CTFx"]
    server = client[str(guild.name).replace(' ', '-')]['ctfs']
    ctf = server.find_one({'name': channel_name})

    url = creds[str(guild.name).replace(' ', '-') + "." + channel_name]["site"]
    if url[-1] == "/": url = url[:-1]
    s = requests.session()
    r = s.get("{}/login".format(url))
    if fingerprints[0] in r.text:
        user = creds[str(guild.name).replace(' ', '-') + "." + channel_name]["user"]
        password = creds[str(guild.name).replace(' ', '-') + "." + channel_name]["pass"]
        try:
            nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
        except: # sometimes errors happen here - possibly due to CTFd versioning
            try:
                nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
            except:
                raise NonceNotFound("Was not able to find the nonce token from login. Could not check if aliases are correct.")

        # Login and check if credentials are valid
        r = s.post(f"{url}/login", data={"name": user, "password": password, "nonce": nonce})
        if "Your username or password is incorrect" in r.text:
            raise InvalidCredentials("Invalid login credentials. Could not check if aliases are correct.")

        # Get aliases for all members
        aliases = []
        members = s.get(f"{url}/api/v1/teams/me").json()['data']['members']
        for m_id in members:
            alias = s.get("{}/api/v1/users/{}".format(url, m_id)).json()
            aliases.append(alias['data']['name'])

        # iterate members in competition and check if they are in aliases
        members_not = []
        for name, attr in ctf['members'].items():
            if not attr['alias'] in aliases:
                members_not.append(name)

        if len(members_not) > 0:
            m = ""
            for mem in members_not:
                it = mem.split("#")
                user = discord.utils.get(guild.members, name = it[0], discriminator = it[1])
                m += user.mention + " "
            m += "\nYou have invalid aliases! "
            m += "Send `>ctf join [alias]` to update your alias or this will not count for your scoring."
            raise InvalidCredentials(m)

    else:
        raise InvalidCredentials("CTF is not based on CTFd - could not check if aliases are correct.")

# This occurs after the calculate() method to update all three rankings
def do_rankings(server_name, ctf_name, team_name):
    server = client[server_name.replace(' ', '-')]
    info_db = server['info']
    members = server['members']

    ext_names = ['_overall', '_semester', '_year']
    for e in ext_names:
        # Create overall rankings
        rankings = {}
        overall_r = []
        already_got = []
        while (len(overall_r) < members.count()):
            highest = -1
            p = None
            for person in members.find():
                if person[f'ratings{e}']['overall'] > highest and not person['name'] in already_got:
                    highest = person[f'ratings{e}']['overall']
                    p = person
            already_got.append(p['name'])
            overall_r.append({'name': p['name'], 'score': p[f'ratings{e}']['overall']})
        rankings['overall'] = overall_r

        # Create rankings for each category
        for cat in chall_aliases.keys():
            arr = []
            already_got = []
            while (len(arr) < members.count()):
                highest = -1
                p = None
                for person in members.find():
                    if person[f'ratings{e}'][cat]['score'] > highest and not person['name'] in already_got:
                        highest = person[f'ratings{e}'][cat]['score']
                        p = person
                already_got.append(p['name'])
                arr.append({'name': p['name'], 'score': p[f'ratings{e}'][cat]['score']})
            rankings[cat] = arr

        # Update Guild Information
        comp_arr = info_db.find_one({'name': server_name})[f'competitions{e}']
        if comp_arr == []:
            comp_arr = [ctf_name]
        else:
            comp_arr.append(ctf_name)

        # Update DB with all calculated information
        info_db.update({'name': server_name}, {"$set": {f'rankings{e}': rankings, f'competitions{e}': comp_arr}}, upsert=True)

# Update each member's scores who competed in competition
def calculate(server_name, ctf_name, team_name):
    # Fetch Databases
    server = client[server_name.replace(' ', '-')]
    info_db = server['info']
    members = server['members']
    ctf = server['ctfs'].find_one({'name': ctf_name})
    num_members = len(ctf['teams'][team_name]['members'].keys())

    # if CTF weight is undefined, default to 25
    weight = ctf['weight']
    if weight == 0:
        weight = 25


    # Calculate numerators and denominators for each member of competition
    for name, mem_points in ctf['teams'][team_name]['members'].items():
        # Add CTF to competed CTFs in member profile
        member = members.find_one({'name': name})
        ext_names = ['_overall', '_semester', '_year']
        for e in ext_names:
            arr = member[f'competed{e}']
            if arr == []:
                arr = [ctf_name]
            else:
                arr.append(ctf_name)

            # Calculate each category numerator and denominator
            length = len(arr)
            ratings = member[f'ratings{e}']
            inv_names = ["alias", "name", "solves"]
            for cat, val in mem_points.items():
                if not (cat in inv_names) and not (ctf['points'][cat] == 0):
                    solved_points = val
                    total_points = ctf['points'][cat]
                    weight = ctf['weight']
                    numerator = solved_points*weight
                    denominator = total_points*weight
                    ratings[cat]['numerator'] = ratings[cat]['numerator'] + numerator
                    ratings[cat]['denominator'] = ratings[cat]['denominator'] + denominator
                    ratings[cat]['score'] = 100*(ratings[cat]['numerator'] / ratings[cat]['denominator'])

            # Calculate overall
            overall = 0
            for cat, val in member[f'ratings{e}'].items():
                if cat != "overall":
                    overall += val['score']
            overall = overall / (len(member[f'ratings{e}'].keys()) - 1)
            ratings['overall'] = overall

            # Update member's DB and set boolean to True
            members.update({'name': name}, {"$set": {f'ratings{e}': ratings, f'competed{e}': arr}}, upsert=True)
    server['ctfs'].update({'name': ctf_name}, {"$set": {'calculated?': True, 'weight': weight}}, upsert=True)

# Grab information for specified challenge on CTFd
def get_one_CTFd(ctx, url, username, password, s, chall):
    r = s.get(f"{url}/login")
    try:
        nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
    except: # sometimes errors happen here - possibly due to CTFd versioning
        try:
            nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
        except:
            try:
                nonce = r.text.split("name=\"csrf-token\" content=\"")[1].split('">')[0]
            except:
                raise NonceNotFound("Was not able to find the nonce token from login.")

    # Login and check if credentials are valid
    r = s.post(f"{url}/login", data={"name": username, "password": password, "nonce": nonce})
    if "Your username or password is incorrect" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    # Get challenge ID
    all_challenges = s.get(f"{url}/api/v1/challenges").json()
    chall_id = -1
    for c_hash in all_challenges['data']:
        if c_hash['name'].lower() == chall.lower():
            chall_id = c_hash['id']
            break

    # If chall name was not found, return with error message
    if chall_id == -1:
        raise InvalidCredentials("Challenge not found")

    # Grab challenge file and attach in message
    challenge_info = s.get("{}/api/v1/challenges/{}".format(url, chall_id)).json()

    # Get attachments
    files = []
    m = ""
    for i in range(len(challenge_info['data']['files'])):
        fn = challenge_info['data']['files'][i].split('?')[0].split('/')[-1]
        u = "{}{}".format(url, challenge_info['data']['files'][i])
        contents = s.get(u).text.encode()
        #contents = contents
        with open(fn, 'wb') as f:
            f.write(contents)
        files.append(fn)
        m += fn + ', '

    challenge_info['data']['m'] = m
    challenge_info['data']['files'] = files
    return challenge_info

# Grab information for specified challenge on rCTF
def get_one_rCTF(ctx, url, token, s, chall):
    heads = {
        "Content-Type": "application/json",
        "Authorization": "Bearer null"
    }
    r = s.post(f"{url}/api/v1/auth/login", json={"teamToken": token}, headers=heads)
    if "Your token is incorrect" in r.text or "badToken" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    r_json = r.json()
    bearer_token = r_json['data']['authToken']
    heads = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
        "Referer": "{}/challs".format(url),
        "Authorization": "Bearer {}".format(bearer_token)
    }

    # Get challenge information
    r_chals = s.get(f"{url}/api/v1/challs", headers=heads)
    all_challs = r_chals.json()
    chall_dict = -1
    for c_hash in all_challs['data']:
        if c_hash['name'].lower() == chall.lower():
            chall_dict = c_hash
            break

    # If chall name was not found, return with error message
    if chall_dict == -1:
        raise InvalidCredentials("Challenge not found")

    # Grab challenge file and attach in message
    print(chall_dict)
    return chall_dict

# Grab information for specified challenge on CTFd
def get_one_RACTF(ctx, url, username, password, s, chall):
    r = s.get(f"{url}/login")
    try:
        apiUrl = r.text.split("apiDomain:\'")[1].split('\'')[0]
    except:
        raise NonceNotFound("Was not able to find the apiUrl from login.")
    try:
        r = s.post(f"{apiUrl}/api/v2/auth/login/", data={"username": username, "password": password})
        token = r.json()['d']['token']
    except: # sometimes errors happen here - possibly due to CTFd versioning
        raise NonceNotFound("Authentication failed: " + str(r.text))

    heads = {
        "Authorization": "Token {}".format(token)
    }

    # Get challenge ID
    all_challenges = s.get(f"{apiUrl}/api/v2/challenges/categories/", headers=heads).json()['d']
    chall_info = {}
    for cat_dict in all_challenges:
        cat = cat_dict['name']
        for ch in cat_dict['challenges']:
            if ch['name'].lower() == chall.lower():
                chall_info = ch
                break

        if len(chall_info.keys()) > 0:
            for real_chall_name, aliases in chall_aliases.items():
                if cat.lower() in aliases:
                    chall_info['cat'] = real_chall_name
                    break

            if not ('cat' in chall_info.keys()):
                chall_info['cat'] = 'misc'
            break

    # If chall name was not found, return with error message
    if len(chall_info.keys()) == 0:
        raise InvalidCredentials("Challenge not found")

    # Get attachments
    files = []
    m = ""
    for i in range(len(chall_info['files'])):
        fn = chall_info['files'][i]['url'].split('/')[-1]
        contents = s.get(chall_info['files'][i]['url']).text.encode()
        with open(fn, 'wb') as f:
            f.write(contents)
        files.append(fn)
        m += fn + ', '

    # Grab challenge file and attach in message
    challenge_info = {'name': chall_info['name'], 'description': chall_info['description'],
                      'category': chall_info['cat'], 'solves': chall_info['solve_count'],
                      'score': chall_info['score'], 'files': files, 'm': m}
    return challenge_info

# Grab all challenge information from competition CTFd and update database
def get_challenges_CTFd(ctx, url, username, password, s):
    r = s.get(f"{url}/login")
    try:
        nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
    except: # sometimes errors happen here - possibly due to CTFd versioning
        try:
            nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
        except:
            try:
                nonce = r.text.split("name=\"csrf-token\" content=\"")[1].split('">')[0]
            except:
                raise NonceNotFound("Was not able to find the nonce token from login.")

    # Login and check if credentials are valid
    r = s.post(f"{url}/login", data={"name": username, "password": password, "nonce": nonce})
    if "Your username or password is incorrect" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    # Get information from API
    all_challenges = s.get(f"{url}/api/v1/challenges").json()
    team_info = s.get(f"{url}/api/v1/teams/me").json()
    team_solves = s.get(f"{url}/api/v1/teams/me/solves").json()
    if 'success' not in team_solves: # ctf is user based
        team_info = s.get(f"{url}/api/v1/users/me").json()
        team_solves = s.get(f"{url}/api/v1/users/me/solves").json()

    # Variables
    challenges = {}
    point_info = {
        "crypto": 0, "forensics": 0, "misc": 0, "osint": 0, "web exploitation": 0,
        "pwn": 0, "reversing": 0, "tryhackme": 0, "total": 0
    }
    solved_points = 0
    server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
    team_name = str(ctx.channel)
    teams = server.find_one({'name': str(ctx.message.channel.category)})['teams']
    members = server.find_one({'name': str(ctx.message.channel.category)})['teams'][team_name]['members']

    # Reset points to 0
    inv_names = ["alias", "name", "solves"]
    for k, v in members.items():
        for cat, _ in v.items():
            if not cat in inv_names : members[k][cat] = 0

    # Add all challenges
    if all_challenges['success'] == True:
        for chall in all_challenges['data']:
            cat = chall['category']
            challname = chall['name']
            value = chall['value']
            point_info['total'] += value

            # Add points for category - misc if not found
            for real_chall_name, aliases in chall_aliases.items():
                if cat.lower() in aliases:
                    cat = real_chall_name
                    point_info[real_chall_name] += value
                    break
            if point_info[real_chall_name] == 0:
                cat = "misc"
                point_info["misc"] += value

            chall_entry = {'name': challname, 'solved': False, 'solver': '', 'points': value}
            if cat in challenges.keys():
                challenges[cat].append(chall_entry)
            else:
                challenges[cat] = [chall_entry]
    else:
        raise Exception("Error making request")

    # Add team solves
    #print(challenges)
    if team_solves['success'] == True:
        for solve in team_solves['data']:
            # Get challenge info
            cat = solve['challenge']['category'].lower()
            challname = solve['challenge']['name']
            solver = solve['user']
            value = solve['challenge']['value']
            solved_points += value

            # Get user info
            r_user = s.get(f"{url}/api/v1/users/{solver}")
            user_profile = r_user.json()
            solver = user_profile['data']['name']

            found = 0
            for real_chall_name, aliases in chall_aliases.items():
                if cat.lower() in aliases:
                    cat = real_chall_name
                    found = 1
                    break
            if found == 0:
                cat = "misc"

            # Add points for member who solved it for specific category
            for name, attr in members.items():
                if attr["alias"] == solver:
                    attr[cat] += value
                    #print(attr['solves'])
                    attr['solves'][challname] = value

            # Change challenge_solved info if solved by team
            for i in range(len(challenges[cat])):
                if challname == challenges[cat][i]['name']:
                    challenges[cat][i]['solved'] = True
                    challenges[cat][i]['solver'] = solver

        # add solver and solved values

    # Add total points to db
    rank = ""
    if "place" in team_info['data'].keys() and team_info['data']['place']:
        rank += team_info['data']['place']

    teams[team_name]['members'] = members
    teams[team_name]['rank'] = rank
    teams[team_name]['solved points'] = solved_points

    ctf_info = {'points': point_info, 'teams': teams}
    #server.update({'name': str(ctx.message.channel)}, {"$unset": {'total points': ""}}, upsert=True)
    server.update({'name': str(ctx.channel.category)}, {"$set": ctf_info}, upsert=True)
    return challenges

# Grab all challenge information from competition rCTF and update database
def get_challenges_rCTF(ctx, url, token, s):
    heads = {
        "Content-Type": "application/json",
        "Authorization": "Bearer null"
    }
    r = s.post(f"{url}/api/v1/auth/login", json={"teamToken": token}, headers=heads)
    if "Your token is incorrect" in r.text or "badToken" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    r_json = r.json()
    bearer_token = r_json['data']['authToken']

    heads = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
        "Referer": "{}/challs".format(url),
        "Authorization": "Bearer {}".format(bearer_token)
    }

    # Get challenge information
    r_chals = s.get(f"{url}/api/v1/challs", headers=heads)
    all_challs = r_chals.json()

    # Get team solves
    r_solves = s.get(f"{url}/api/v1/users/me", headers=heads)
    team_solves = r_solves.json()

    #print(all_challs)
    #print(team_solves)

    # Variables
    challenges = {}
    total_points = 0
    server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']

    print(all_challs['kind'])

    # Add all challenges
    if all_challs['kind'] == "goodChallenges":
        for chall in all_challs['data']:
            cat = chall['category']
            challname = chall['name']
            value = chall['points']
            total_points += value
            chall_entry = {'name': challname, 'solved': False, 'solver': '', 'points': value}
            if cat in challenges.keys():
                challenges[cat].append(chall_entry)
            else:
                challenges[cat] = [chall_entry]
    else:
        raise Exception("Error making request")

    # Add total points to db
    ctf_info = {'name': str(ctx.message.channel), 'total points': total_points}
    server.update({'name': str(ctx.message.channel)}, {"$unset": {'total points': ""}}, upsert=True)
    server.update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)

    # Add team solves
    if team_solves['kind'] == "goodUserData":
        print("goodUserData")
        for solve in team_solves['data']['solves']:
            # Get challenge info
            cat = solve['category']
            challname = solve['name']

            # Change challenge solved info if solved by team
            for i in range(len(challenges[cat])):
                if challname == challenges[cat][i]['name']:
                    challenges[cat][i]['solved'] = True

    return challenges

# Grab all challenge information from competition CTFd and update database
def get_challenges_RACTF(ctx, url, username, password, s):
    r = s.get(f"{url}/login")
    try:
        apiUrl = r.text.split("apiDomain:\'")[1].split('\'')[0]
    except:
        raise NonceNotFound("Was not able to find the apiUrl from login.")
    try:
        r = s.post(f"{apiUrl}/api/v2/auth/login/", data={"username": username, "password": password})
        token = r.json()['d']['token']
    except: # sometimes errors happen here - possibly due to CTFd versioning
        raise NonceNotFound("Authentication failed: " + str(r.text))

    heads = {
        "Authorization": "Token {}".format(token)
    }

    # Get information from API
    all_challenges = s.get(f"{apiUrl}/api/v2/challenges/categories/", headers=heads).json()['d']
    team_info = s.get(f"{apiUrl}/api/v2/team/self/", headers=heads).json()['d']
    team_solves = team_info['solves']

    # Variables
    challenges = {}
    point_info = {
        "crypto": 0, "forensics": 0, "misc": 0, "osint": 0, "web exploitation": 0,
        "pwn": 0, "reversing": 0, "tryhackme": 0, "total": 0
    }
    solved_points = 0
    server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
    team_name = str(ctx.channel.name)
    teams = server.find_one({'name': str(ctx.message.channel.category)})['teams']
    members = server.find_one({'name': str(ctx.message.channel.category)})['teams'][team_name]['members']

    # Reset points to 0
    inv_names = ["alias", "name", "solves"]
    for k, v in members.items():
        for cat, _ in v.items():
            if not cat in inv_names : members[k][cat] = 0

    # Add all challenges
    if len(all_challenges) > 0:
        for cat_dict in all_challenges:
            cat = cat_dict['name']
            for chall in cat_dict['challenges']:
                if len(chall['unlock_requirements']) > 0:
                    challname = 'LOCKED CHALLENGE'
                    value = 0
                else:
                    challname = chall['name']
                    value = chall['score']
                point_info['total'] += value

                # Add points for category - misc if not found
                for real_chall_name, aliases in chall_aliases.items():
                    if cat.lower() in aliases:
                        cat = real_chall_name
                        point_info[real_chall_name] += value
                        break
                if point_info[real_chall_name] == 0:
                    cat = "misc"
                    point_info["misc"] += value

                chall_entry = {'name': challname, 'solved': False, 'solver': '', 'points': value}
                if cat in challenges.keys():
                    challenges[cat].append(chall_entry)
                else:
                    challenges[cat] = [chall_entry]
    else:
        raise Exception("Error adding all challenges")

    # Add team solves
    #print(challenges)
    for solve in team_solves:
        # not sure why, but they put None values sprinkled in this structure
        if solve == None:
            continue

        # Get challenge info
        challname = solve['challenge_name']

        # search for chall name
        cat = ""
        for cat_name, cat_challs in challenges.items():
            for ch in cat_challs:
                if ch['name'] == challname:
                    cat = cat_name
                    break
            if cat != "":
                break

        solver = solve['solved_by_name']
        solver_id = solve['solved_by']
        value = solve['points']
        solved_points += value

        found = 0
        for real_chall_name, aliases in chall_aliases.items():
            if cat.lower() in aliases:
                cat = real_chall_name
                found = 1
                break
        if found == 0:
            cat = "misc"

        # Add points for member who solved it for specific category
        for name, attr in members.items():
            if attr["alias"] == solver:
                attr[cat] += value
                #print(attr['solves'])
                attr['solves'][challname] = value

        # Change challenge_solved info if solved by team
        for i in range(len(challenges[cat])):
            if challname == challenges[cat][i]['name']:
                challenges[cat][i]['solved'] = True
                challenges[cat][i]['solver'] = solver

    # Add total points to db
    leaderboard_arr = s.get(f"{apiUrl}/api/v2/leaderboard/ctftime/", headers=heads).json()['standings']
    for team in leaderboard_arr:
        if team['team'] == team_info['name']:
            rank = team['pos']
            break
    rank = place(int(rank))

    teams[team_name]['members'] = members
    teams[team_name]['rank'] = rank
    teams[team_name]['solved points'] = solved_points

    ctf_info = {'points': point_info, 'teams': teams}
    #server.update({'name': str(ctx.message.channel)}, {"$unset": {'total points': ""}}, upsert=True)
    server.update({'name': str(ctx.channel.category).lower()}, {"$set": ctf_info}, upsert=True)
    return challenges

# generate keypair for CTF password
def rsa_encrypt(plaintext, ctfname, username):
    keypair = RSA.generate(2048)
    keys[f'{ctfname}_{username}'] = {'e': keypair.e, 'd': keypair.d, 'n': keypair.n, 'p': keypair.p, 'q': keypair.q}
    pickle.dump(keys, open("passwords.p", "wb"))
    ciphertext = pow(bytes_to_long(plaintext.encode()), keypair.e, keypair.n)
    return str(ciphertext)

# decrypt password for CTFBot use with use of keypair
def rsa_decrypt(ciphertext, ctfname, username):
    keypair = keys[f'{ctfname}_{username}']
    plaintext = pow(int(ciphertext), keypair['d'], keypair['n'])
    plaintext = long_to_bytes(plaintext).decode()
    return plaintext

#################################### CLASSES ###################################
class InvalidProvider(Exception):
    pass
class InvalidCredentials(Exception):
    pass
class NonceNotFound(Exception):
    pass

class CTF(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.creds = {} # Stores credentials locally (not in database)
        self.current = [] # Stores started ctfs
        #self.get_info.start()

    #@tasks.loop(minutes=1.0)
    async def get_info(self):
        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())

        # Get chall info for each running competition
        for guild in self.bot.guilds:
            server = client[str(guild.name).replace(' ', '-')]
            for ctf in server['ctfs'].find():
                # Pull challenges at very START and END of competition
                if ((unix_now - ctf['start'] < 122) and (unix_now - ctf['start'] > 0)) or \
                ((ctf['end'] - unix_now > 0) and (ctf['end'] - unix_now < 122)):
                    # Add name to current array
                    if not ctf['name'] in self.current:
                        self.current.append(ctf['name'])

                    # Check aliases
                    if str(guild.name).replace(' ', '-') + "." + str(ctf['name']) in self.creds:
                        c_id = 0
                        for channel in guild.channels:
                            if channel.name == ctf['name']:
                                print(channel.id)
                                c_id = channel.id
                                break
                        ch = self.bot.get_channel(c_id)
                        try:
                            check_aliases(guild, self.creds, str(ctf['name'])) # Check if all aliases are good!
                            await ch.send("Yep, everyone has correct aliases")
                        except InvalidCredentials as icm:
                            await ch.send(icm)

                # Right after competition ends
                elif unix_now - ctf['end'] < 122:
                    self.current.remove(ctf['name'])
                    c_id = 0

                    # Get channel id to send info
                    c_id = 0
                    for channel in guild.channels:
                        if channel.name == ctf['name']:
                            c_id = channel.id
                            break
                    ch = self.bot.get_channel(c_id)

                    # Display Statistics from competition
                    # Add simple team stats
                    ti = "Stats from {}".format(ctf['name'])
                    des = "**Members:** "
                    for name, v in ctf['members'].items():
                        des += "{}, ".format(name.split("#")[0])
                    des = des[:-2]
                    val = "{} out of {} points".format(ctf['solved points'], ctf['points']['total'])
                    rank = ctf['rank']
                    if rank == "": rank = "???"
                    emb = discord.Embed(title=ti, description=des, colour=10181046)
                    emb.add_field(name="Score", value=val, inline=True)
                    emb.add_field(name="Place", value=rank, inline=True)
                    emb.set_thumbnail(url=str(ctf['logo']))
                    await ch.send(embed=emb)

                    # Add all members stats
                    for name, attr in ctf['members'].items():
                        total = 0
                        ti = "{}'s Details".format(name.split('#')[0])
                        emb = discord.Embed(title=ti, description="[scored] / [total]", colour=10181046)
                        for cat, val in attr.items():
                            if not cat == "alias" and not val == 0:
                                nm = ' '.join([c.capitalize() for c in cat.split(' ')])
                                val2 = f"{val}" + " / {}".format(ctf['points'][cat])
                                emb.add_field(name=nm, value=val2, inline=False)
                                total += val

                        emb.set_thumbnail(url=(server['members'].find_one({'name': name})['pfp']))
                        emb.add_field(name="Total Points", value=total, inline=True)
                        await ch.send(embed=emb)
                        print("got user embed - {}".format(name))

                    # Calculate scores
                    calculate(str(guild.name), ctf)
                    do_rankings(str(guild.name), ctf)

    @commands.group()
    async def ctf(self, ctx):
        if ctx.invoked_subcommand is None:
            await ctx.channel.send("Invalid command. Run `>help ctf` for information on **ctf** commands.")

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_channel()
    async def create(self, ctx, link):
        # If general competition not on ctftime
        if not ("https://ctftime.org" in str(link)):
            category = discord.utils.get(ctx.guild.categories, name="CTF")
            await ctx.guild.create_text_channel(name=str(link), category=category)
            await ctx.guild.create_role(name=str(link), mentionable=True)
            await ctx.message.add_reaction("✅")
            return

        # Parse CTFTime Link
        if link[-1] == "/": link = link[:-1]
        event_id = link.split("/")[-1]
        link = "https://ctftime.org/api/v1/events/{}/".format(event_id)
        head = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0'}

        # Get and parse JSON data for competition
        r_event = requests.get(url=link, headers=head)

        # Error message when CTFTime is down and doesn't do anything
        if r_event.status_code == 404:
            await ctx.channel.send("CTFTime is currently down. Try again later!")
            return

        event_json = r_event.json()

        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())
        (ctf_start, ctf_end) = (parse(event_json['start'].replace('T', ' ').split('+', 1)[0]), parse(event_json['finish'].replace('T', ' ').split('+', 1)[0]))
        (unix_start, unix_end) = (int(ctf_start.replace(tzinfo=timezone.utc).timestamp()), int(ctf_end.replace(tzinfo=timezone.utc).timestamp()))
        (ctf_hours, ctf_days) = (str(event_json["duration"]["hours"]), str(event_json["duration"]["days"]))
        ctf_info = {
            "name": event_json["title"].replace(' ', '-').replace('.', '_').replace('!', '').replace('@', '').replace('(', '').replace(')', '').lower(),
            "text_channel": event_json["title"].replace(' ', '-').replace('.', '_').replace('!', '').replace('@', '').replace('(', '').replace(')', '').lower(),
            "website": event_json["url"], "weight": event_json["weight"],
            "description": event_json["description"], "start": unix_start,
            "end": unix_end, "duration": (((ctf_days + " days, ") + ctf_hours) + " hours"),
            "calculated?": False, "logo": event_json["logo"], "teams": {}
        }

        # Update CTF DB for guild
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        server.update({'name': ctf_info["name"]}, {"$set": ctf_info}, upsert=True)

        # Discord server stuff
        ctf_name = ctf_info["name"]
        if ctf_name not in [c.name for c in ctx.guild.categories]:
            cat = await ctx.guild.create_category(ctf_name)
            length = len(ctx.guild.categories)
            await cat.edit(position=length-2)
        category = discord.utils.get(ctx.guild.categories, name=ctf_name)

        await ctx.guild.create_text_channel(name=ctf_name, category=category)
        await ctx.guild.create_role(name=ctf_name, mentionable=True)
        await ctx.message.add_reaction("✅")

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_channel()
    @in_ctf_channel()
    async def form(self, ctx, teamname):
        servcat = str(ctx.message.channel)
        teamname = teamname.replace(' ','-').lower() + '-' + str(ctx.channel.category).lower()
        category = discord.utils.get(ctx.guild.categories, name=servcat)
        if category == None: # Checks if category exists, if it doesn't it will create it.
            cat = await ctx.guild.create_category(servcat)
            await cat.edit(position=2)
            category = discord.utils.get(ctx.guild.categories, name=servcat)

        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf_name = server.find_one({'name': str(ctx.message.channel)})

        # Checks to see if team has alreasdy been formed
        if teamname in ctf_name['teams']:
            await ctx.send("This team has already been formed! If you wish to make a separate team, please use a different team name.")
            return

        # Creates the team info for the database and for a role and channel
        team_info = {
            "name": teamname,
            "members": {},
            "creds": {}
        }

        # Update CTF DB for guild and for the team being made
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel)})
        teams = ctf['teams']
        teams[teamname] = team_info

        server.update({'name': str(ctx.message.channel)}, {"$set": {'teams': teams}}, upsert=True)

        # create role
        await ctx.guild.create_role(name=teamname, mentionable=True)
        await ctx.guild.create_text_channel(name=teamname, category=category)
        await ctx.guild.create_voice_channel(name=teamname, category=category)

        roles = ctx.guild.roles
        channels = ctx.guild.channels
        voice_channels = ctx.guild.voice_channels
        for r in roles:
            if r.name == teamname:
                role = r
        for c in channels:
            if c.name == teamname:
                await c.set_permissions(ctx.guild.default_role, send_messages=False, read_messages=False)
                await c.set_permissions(role, read_messages=True, send_messages=True)
        for vc in voice_channels:
            if vc.name == teamname:
                await vc.set_permissions(ctx.guild.default_role, send_messages=False, read_messages=False)
                await vc.set_permissions(role, read_messages=True, send_messages=True)

        await ctx.message.add_reaction("✅")

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_channel()
    async def disband(self, ctx):
        teamname = str(ctx.message.channel)
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel.category)})
        if ctf == None:
            await ctx.channel.send('CTF does not exists for some reason?')
            return

        # Checks if team exists
        teams = ctf['teams']
        if teamname not in teams:
            await ctx.send("This is not a team channel")
            return

        del teams[teamname]
        server.update({'name': str(ctx.message.channel.category)}, {"$set": {'teams': teams}}, upsert=True)
        channel = discord.utils.get(ctx.guild.text_channels, name=str(ctx.message.channel.category).lower())
        ch = self.bot.get_channel(channel.id)
        #print(ctx.guild.channels)
        await ch.send(f"`{str(ctx.message.channel).split('-')[0]}` disbanded")

        # remove role and channel
        try:
            role = discord.utils.get(ctx.guild.roles, name=teamname)
            await role.delete()
            await ch.send(f"`{role.name}` role deleted")
            for vc in ctx.guild.voice_channels:
                if (str(vc.name) == teamname) and (str(vc.category) == str(ctx.message.channel.category)):
                    await self.bot.get_channel(vc.id).delete()
                    break
            for c in ctx.guild.channels:
                if (str(c.name) == teamname) and (str(c.category) == str(ctx.message.channel.category)):
                    await self.bot.get_channel(c.id).delete()
                    break
        except: # role most likely already deleted with archive
            pass

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_channel()
    @in_ctf_channel()
    async def add(self, ctx, user: discord.User, alias, teamname):
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel)})
        teams = ctf['teams']
        teamname = teamname.replace(' ','-').lower() + '-' + str(ctx.channel.category).lower()

        # Check if team exists
        if not (teamname in teams.keys()):
            await ctx.channel.send("The team **{}** does not exist!".format(teamname.split('-')[0]))
            return

        # Check if user belongs to team already
        for t in teams.keys():
            if str(user) in teams[t]['members']:
                await ctx.channel.send("{} already belongs to team {}".format(str(user), t))
                return

        # get member
        channel = discord.utils.get(ctx.guild.text_channels, name=teamname)
        member = ctx.guild.get_member(user.id)

        # get role & add role to user
        roles = ctx.guild.roles
        role = ""
        for r in roles:
            if r.name == teamname:
                await member.add_roles(r)

        # add member to team in DB
        #member_info = { "name": str(user), "alias": alias, "solves": []}
        member_info = { "name": str(user), "alias": alias, "crypto": 0, "forensics": 0,
                        "misc": 0, "osint": 0, "web exploitation": 0, "pwn": 0,
                        "reversing": 0, "tryhackme": 0, "solves": {}}
        teams[teamname]['members'][str(user)] = member_info
        server.update({'name': str(ctx.message.channel)}, {"$set": {'teams': teams}}, upsert=True)

        await ctx.message.add_reaction("✅")
        await channel.send("{} has joined {}!".format(user.mention, teamname.split('-')[0]))

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_channel()
    @in_ctf_channel()
    async def rm(self, ctx, user: discord.User, teamname):
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel)})
        teams = ctf['teams']
        teamname = teamname.replace(' ','-').lower() + '-' + str(ctx.channel.category).lower()

        # Check if team exists
        if not (teamname in teams.keys()):
            await ctx.channel.send("The team **{}** does not exist!".format(teamname.split('-')[0]))
            return

        # Check if user belongs to the team
        belongs = False
        if str(user) in teams[teamname]['members']:
            belongs = True

        if belongs == False:
            await ctx.channel.send("{} is not on team {}".format(str(user), teamname.split('-')[0]))
            return

        # get member
        channel = discord.utils.get(ctx.guild.text_channels, name=teamname)
        member = ctx.guild.get_member(user.id)

        # get role & remove role from user
        roles = ctx.guild.roles
        role = ""
        for r in roles:
            if r.name == teamname:
                await member.remove_roles(r)

        # remove member from team in DB
        teams[teamname]['members'].pop(str(user))
        server.update({'name': str(ctx.message.channel)}, {"$set": {'teams': teams}}, upsert=True)

        await ctx.message.add_reaction("✅")
        await channel.send("{} has been removed from {}".format(user.mention, teamname.split('-')[0]))

    @ctf.command()
    @in_channel()
    async def change(self, ctx, alias, user: discord.User=None):
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.channel.category)})
        teams = ctf['teams']
        teamname = str(ctx.message.channel)

        # Check if team exists
        if not (teamname in teams.keys()):
            await ctx.channel.send("This command only works in a team channel")
            return

        if user is None:
            user = ctx.message.author
        else:
            permissions = ctx.message.author.permissions_in(ctx.message.channel)
            if not (permissions.manage_messages):
                await ctx.channel.send(f'You do not have the ability to change other members\' aliases')
                return

        # Check if user is not a part of the team
        if not (str(user) in teams[teamname]['members'].keys()):
            await ctx.channel.send(f'{user} is not a part of this team!')
            return

        teams[teamname]['members'][str(user)]['alias'] = alias
        server.update({'name': str(ctx.channel.category)}, {"$set": {'teams': teams}}, upsert=True)
        await ctx.channel.send("{} has changed their alias to **{}**".format(user.mention, alias))

    @ctf.command()
    @in_channel()
    async def members(self, ctx, teamname):
        server = client[str(ctx.guild.name).replace(' ', '-')]
        ctf = server['ctfs'].find_one({'name': str(ctx.message.channel)})
        teamname = teamname.replace(' ','-').lower() + '-' + str(ctx.channel.category).lower()
        if ctf == None:
            ctf = server['ctfs'].find_one({'name': str(ctx.message.channel.category)})
            if ctf == None:
                await ctx.channel.send("Run this command under the specific competition category")
                return

        if teamname not in ctf['teams']:
            await ctx.channel.send("This team does not exist!")
            return

        # add member to team in DB
        member_list = ctf['teams'][teamname]['members']
        ### print(member_list)
        for m in member_list:
            solve_arr = member_list[m]['solves']
            if len(solve_arr.keys()) == 0:
                solve_arr = "[]"
            else:
                solve_arr = ", ".join(solve_arr)
            member = server['members'].find_one({'name': m})
            ti = member_list[m]['alias']
            if member['ratings_overall']['overall'] == 0:
                show = 0
            else:
                show = round(member['ratings_overall']['overall'], 3)
            des = "Server Rating: {}".format(show)
            emb = discord.Embed(title=ti, description=des, colour=1752220)
            emb.add_field(name="Solves: ", value=str(solve_arr), inline=True)
            emb.set_thumbnail(url=member['pfp'])
            await ctx.channel.send(embed=emb)

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_ctf_channel()
    async def delete(self, ctx):
        # Delete role from server, delete entry from db
        try:
            role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
            await role.delete()
            await ctx.send(f"`{role.name}` role deleted")
        except: # role most likely already deleted with archive
            pass
        client[str(ctx.guild.name).replace(' ', '-')]['ctfs'].remove({'name': str(ctx.message.channel)})
        await ctx.send(f"`{str(ctx.message.channel)}` deleted from db")

        # Deleting channels
        ctfname = str(ctx.message.channel)
        for channel in ctx.guild.channels:
            if str(channel.category).lower() == ctfname.lower():
                role = discord.utils.get(ctx.guild.roles, name=str(channel).lower())
                if channel != None:
                    await channel.delete()
                try:
                    if role != None:
                        print(f"`{role.name}` role deleted")
                        await role.delete()
                except: # just in case discord wacks out
                    pass

        # delete category
        for cat in ctx.guild.categories:
            if str(cat.name).lower() == ctfname.lower():
                await cat.delete()

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_ctf_channel()
    async def archive(self, ctx):
        ctfname = str(ctx.message.channel)
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        if role != None:
            await ctx.channel.send(f"`{role.name}` role deleted, archiving channel.")
            await role.delete()

        # get ctf-general channel and send message there
        for ch in ctx.guild.text_channels:
            if str(ch.category).lower() == "ctf" and str(ch.name) == "ctf-general":
                await ch.send(f'Archived `{ctfname}`')

        print(f'Deep Archiving channel: {ctfname}')
        filename = f"./tmp/{ctfname}.txt"

        # export all message attachments
        counter = 0
        with open(filename, "w+") as file:
            async for msg in ctx.channel.history(limit=None):
                file.write(f"{msg.created_at} - {msg.author.display_name}: {msg.clean_content}\n")
                for a in msg.attachments:
                    await a.save(f"./tmp/{ctfname}-{a.filename}-{counter}")
                    counter += 1

        # combine into tar.gz
        today = date.today()
        d4 = today.strftime("%b-%d-%Y")
        with tarfile.open(f"./archived/{ctfname}-{d4}.tar.gz", "w:gz") as tar_handle:
            for root, dirs, files in os.walk("./tmp/"):
                for file in files:
                    tar_handle.add(os.path.join(root, file))
        os.system("rm ./tmp/*")

        # Deleting channels
        for channel in ctx.guild.channels:
            if str(channel.category).lower() == ctfname.lower():
                role = discord.utils.get(ctx.guild.roles, name=str(channel).lower())
                if channel != None:
                    await channel.delete()
                if role != None:
                    print(f"`{role.name}` role deleted")
                    await role.delete()

        # delete category
        for cat in ctx.guild.categories:
            if str(cat.name).lower() == ctfname.lower():
                await cat.delete()

    @commands.bot_has_permissions(manage_roles=True)
    @ctf.command()
    @in_ctf_channel()
    async def join(self, ctx):
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        user = ctx.message.author
        await user.add_roles(role)
        await ctx.send(f"{user} wants to compete in {str(ctx.message.channel)}!")

    @commands.bot_has_permissions(manage_roles=True)
    @ctf.command()
    @in_ctf_channel()
    async def leave(self, ctx):
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        user = ctx.message.author
        await user.remove_roles(role)
        await ctx.send(f"{user} has left the {str(ctx.message.channel)} team.")

    @ctf.command()
    @in_channel()
    async def setcreds(self, ctx, username, password, site):
        teamname = str(ctx.message.channel)
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.channel.category)})
        teams = ctf['teams']

        # Checks if team exists
        if teamname not in teams:
            await ctx.send("This is not a team channel")
            return
        creds = teams[str(ctx.message.channel)]['creds']

        if site == None:
            site = password
            password = None

        replace_msg = ""
        if creds and len(creds.keys()) > 0:
            if password == None:
                name = creds['token']
                replace_msg += "Replacing credential token"
            else:
                name = creds['user']
                replace_msg += "Replacing **{}**'s creds".format(name)

        if password == None:
            creds = {"token": username, "site": site}
            message = "CTF credentials set. \n**Token:**\t ".format(username) + \
                  "` * * * * * * * * ` \n**Website:**\t` {} `".format(site)
        else:
            ciphertext = rsa_encrypt(password, str(ctx.channel.category), username)
            creds = {"user": username, "pass": ciphertext, "site": site}
            message = "CTF credentials set. \n**Username:**\t` {0} ` ".format(username) + \
                  "\n**Password:**\t` * * * * * * * * ` \n**Website:**\t` {} `".format(site)

        teams[str(ctx.message.channel)]['creds'] = creds
        server.update({'name': str(ctx.channel.category)}, {"$set": {'teams': teams}}, upsert=True)

        # Get rid of pins
        pinned = await ctx.channel.pins()
        for pin in pinned:
            if "CTF credentials set." in pin.content:
                await pin.unpin()

        # Send replace message if need be and send real message
        if not replace_msg == "":
            await ctx.channel.send(replace_msg)
        msg = await ctx.channel.send(message)
        await msg.pin()
        await ctx.message.delete()

    @staticmethod
    async def pull_challs(self, ctx, creds):
        fingerprints = ["CTFd", "meta name=\"rctf-config\"", "CTFx", "challenge-editor"]
        try:
            if not creds:
                await ctx.send("Set credentials with `>ctf setcreds ...`")
                return

            url = creds["site"]

            if url[-1] == "/": url = url[:-1]
            s = requests.session()
            r = s.get("{}/login".format(url))

            # Error message when CTF site is down and then returns
            if r.status_code == 404:
                await ctx.channel.send("CTF site is down. Try pulling challenges when it's up!")
                return

            if fingerprints[0] in r.text or "pbctf" in r.text:
                user = creds["user"]
                password = creds["pass"]
                ctfd_challs = get_challenges_CTFd(ctx, url, user, password, s)
            elif fingerprints[1] in r.text:
                token = self.creds["token"]
                ctfd_challs = get_challenges_rCTF(ctx, url, token, s)
            elif fingerprints[2] in r.text:
                # TODO - Implement CTFx functionality
                raise InvalidProvider("CTFx functionality coming soon - cannot pull challenges.")
            elif fingerprints[3] in r.text:
                user = creds["user"]
                password = creds["pass"]
                ctfd_challs = get_challenges_RACTF(ctx, url, user, password, s)
            else:
                raise InvalidProvider("CTF is not based on CTFd or rCTF - cannot pull challenges.")

            ctf_info = {'name': str(ctx.channel.category).lower(), 'challenges': ctfd_challs}
            server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
            server.update({'name': str(ctx.channel.category).lower()}, {"$set": ctf_info}, upsert=True)
            await ctx.message.add_reaction("✅")
            return
        except InvalidProvider as ipm:
            await ctx.send(ipm)
        except InvalidCredentials as icm:
            await ctx.send(icm)
        except NonceNotFound as nnfm:
            await ctx.send(nnfm)
        except requests.exceptions.MissingSchema:
            await ctx.send("Supply a valid url in the form: `http(s)://ctf.url`")
        except:
            traceback.print_exc()

    @ctf.command()
    @in_channel()
    async def challs(self, ctx, category=None):
        teamname = str(ctx.message.channel)
        ctf_challenge_list = []
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.channel.category).lower()})
        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())
        teams = ctf['teams']

        #Checks if team exists
        if teamname not in teams:
            await ctx.send("This is not a team channel")
            return

        # get creds from db & decrypt password
        creds = teams[str(ctx.message.channel)]['creds']
        try:
            plaintext = rsa_decrypt(creds['pass'], str(ctx.channel.category), creds['user'])
            creds['pass'] = plaintext
        except:
            await ctx.send("Set credentials with `>ctf setcreds ...`")
            return

        if not ctf:
            await ctx.send("Please create a separate channel for this CTF")
            return
        elif (ctf['start'] > unix_now):
            actual_date = datetime.fromtimestamp(ctf['start']).strftime('%H:%M ET on %m/%d/%Y')
            await ctx.send("CTF has not started! Wait until {}".format(actual_date))
            return
        elif (ctf['end'] < unix_now):
            await ctx.send("CTF is over, but I still might have chall info.")
            await CTF.pull_challs(self, ctx, creds)
            if not ctf['calculated?']: # we only want to calculate once
                calculate(str(ctx.guild.name), str(ctx.channel.category).lower(), str(ctx.channel))
                do_rankings(str(ctx.guild.name), str(ctx.channel.category).lower(), str(ctx.channel))
        else:
            await CTF.pull_challs(self, ctx, creds)

        # Print challenges to chat
        ctf = server.find_one({'name': str(ctx.channel.category).lower()}) # update local hash
        if 'challenges' in ctf.keys():
            try:
                ctf_challenge_list = []
                message = ""
                message2 = ""
                #print(ctf['challenges'].items())
                challs = ctf['challenges']
                if not category is None:
                    if category in challs.keys():
                        challs = {category: challs[category]}
                    else:
                        await ctx.send("Invalid category")
                        return
                for k, v in challs.items():
                    if len(message) > 1500:
                        message2 = message
                        message = ""
                    message += "- {0}\n".format(k)
                    for chall in v:
                        message += "[{0}]({1}): ".format(chall['name'], chall['points'])
                        if chall['solved'] == True:
                            message += "Solved - {0}\n".format(chall['solver'])
                        else:
                            message += "Unsolved\n"
                    message += "\n"

                await ctx.send("```md\n{0}```".format(message))
                if message2:
                    await ctx.send("```md\n{0}```".format(message2))
            except:
                traceback.print_exc()
        else:
            print('wtf there are no challs')

    @ctf.command()
    @in_channel()
    async def pull(self, ctx, chall):
        fingerprints = ["CTFd", "meta name=\"rctf-config\"", "CTFx", "challenge-editor"]
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.channel.category)})
        teams = ctf['teams']
        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())

        # get creds from db & decrypt password
        creds = teams[str(ctx.message.channel)]['creds']
        plaintext = rsa_decrypt(creds['pass'], str(ctx.channel.category), creds['user'])
        creds['pass'] = plaintext
        url = creds["site"]

        if not ctf:
            await ctx.send("Please create a separate channel for this CTF")
            return
        elif (ctf['start'] > unix_now):
            await ctx.send("CTF has not started! Wait until {}".format(ctf['start']))
            return
        elif (ctf['end'] < unix_now):
            await ctx.send("CTF is over, but I still might have the challenge here somewhere...")

        # Get challenge info
        try:
            if not creds:
                await ctx.send("Set credentials with `>ctf setcreds ...`")
                return

            if url[-1] == "/": url = url[:-1]
            s = requests.session()
            r = s.get("{}/login".format(url))
            if fingerprints[0] in r.text or 'pbctf' in r.text:
                user = creds["user"]
                password = creds["pass"]
                challenge_info = get_one_CTFd(ctx, url, user, password, s, chall)
                challenge_info = challenge_info['data']
                chall_value = challenge_info['value']
            elif fingerprints[1] in r.text:
                token = creds["token"]
                challenge_info = get_one_rCTF(ctx, url, token, s, chall)
                chall_value = challenge_info['points']
            elif fingerprints[2] in r.text:
                raise InvalidProvider("CTFx functionality coming soon - cannot pull challenge.")
            elif fingerprints[3] in r.text:
                user = creds["user"]
                password = creds["pass"]
                challenge_info = get_one_RACTF(ctx, url, user, password, s, chall)
                chall_value = challenge_info['score']
            else:
                raise InvalidProvider("CTF is not based on CTFd or rCTF - cannot pull challenge.")

            # Send info
            ti = "{} ({})".format(challenge_info['name'], chall_value)
            des = "{}".format(challenge_info['description'])
            emb = discord.Embed(title=ti, description=des, colour=1752220)
            emb.add_field(name="Category", value=challenge_info['category'], inline=True)
            emb.add_field(name="Solves", value=challenge_info['solves'], inline=True)
            m = challenge_info['m']
            files = challenge_info['files']

            if m == "": m = "N/A  "
            emb.add_field(name="Files", value=m[:-2], inline=True)
            await ctx.send(embed=emb)
            for j in files:
                await ctx.channel.send(file=discord.File(j))
                os.remove(j)
            await ctx.message.add_reaction("✅")
        except InvalidProvider as ipm:
            await ctx.send(ipm)
        except InvalidCredentials as icm:
            await ctx.send(icm)
        except NonceNotFound as nnfm:
            await ctx.send(nnfm)
        except requests.exceptions.MissingSchema:
            await ctx.send("Supply a valid url in the form: `http(s)://ctf.url`")
        except:
            traceback.print_exc()

    @ctf.command()
    @in_channel()
    async def solve(self, ctx, chall_name):
        teamname = str(ctx.message.channel)
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel.category)})
        teams = ctf['teams']

        # If team doesn't exist, return message and quit
        if teamname not in teams:
            await ctx.send("You are only able to run this command in a team channel.")
            return

        # check if challenges are pulled!
        if not ('challenges' in ctf.keys()):
            print("Challenges have not been pulled yet. Run the `>ctf challs` command to pull challenges with stored credentials!")
            await ctx.channel.send("Challenges have not been pulled yet. Run the `>ctf challs` command to pull challenges with stored credentials!")
            return
        challenges = ctf['challenges']

        # check if chall name exists!!
        for cat, cat_challs in challenges.items():
            for c in cat_challs:
                if c['name'].lower() == chall_name.lower():
                    print("valid challenge name")
                    c['solver'] = str(ctx.message.author)
                    c['solved'] = True

        #print(teams)
        #print(teams[teamname])
        teams[teamname]['members'][str(ctx.message.author)]['solves'][chall_name.replace(' ','-').lower()] = ctf['challenges'][chall_name]
        server.update({'name': str(ctx.message.channel.category)}, {"$set": {'teams': teams}}, upsert=True)
        await ctx.channel.send("{} has solved `{}`".format(ctx.author.name, chall_name))

#################################### SETUP #####################################
def setup(bot):
    bot.add_cog(CTF(bot))

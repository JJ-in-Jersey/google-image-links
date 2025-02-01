import os
import json
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import google.auth.transport.requests
from googleapiclient.http import MediaFileUpload

from string import Template
from datetime import datetime as dt
import pandas as pd
from pathlib import Path

from tt_file_tools.file_tools import write_df, print_file_exists

BASE_PATH = '/users/jason/fair currents'
SCOPES = ['https://www.googleapis.com/auth/drive']  # Full Drive access
CLIENT_SECRETS_FILE_NAME = 'client_secret_395566799327-1r0m8lib5rv96vucqogeq7bkkcmls0a2.apps.googleusercontent.com.json'
CLIENT_SECRETS_FILE_PATH = os.path.join(BASE_PATH, CLIENT_SECRETS_FILE_NAME)
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'
TOKEN_FILE = os.path.join(BASE_PATH, 'token.json')   # Path to store the token
IMAGE_FOLDER_CODE = '1it58YP-BQlQMdTvVsTQn-E6q7gO0ac5y'
FILE_URL_TEMPLATE = Template('https://drive.google.com/file/d/$fid/view?usp=drive_link')
GOOGLE_NAME = 'google_urls.csv'


def authenticate_user():
    # Authenticates the user using OAuth 2.0 flow.
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE_PATH, scopes=SCOPES, redirect_uri=REDIRECT_URI)
    auth_url, _ = flow.authorization_url(prompt='consent')

    # For local testing, manually copy the authorization code from the URL
    print(f"Please visit this URL to authorize: {auth_url}")
    authorization_code = input("Enter the authorization code: ")

    try:
        flow.fetch_token(code=authorization_code)
    except Exception as e:
        print(f"Error fetching token: {e}")
        return None

    creds = flow.credentials

    # Save the credentials to a file
    with open(TOKEN_FILE, 'w') as token_file:
        # noinspection PyTypeChecker
        json.dump(creds.to_json(), token_file)
    print("Credentials saved to token.json")
    return creds


def load_credentials():
    # Loads credentials from the token file, handling various formats.
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as initial_token_file:
            try:
                credentials_data = json.load(initial_token_file)
                if isinstance(credentials_data, str):
                    credentials_json = json.loads(credentials_data)
                elif isinstance(credentials_data, dict):
                    if 'token' in credentials_data:
                        credentials_json = credentials_data['token']
                    elif 'access_token' in credentials_data:
                        credentials_json = credentials_data
                    else:
                        raise ValueError("Invalid credentials file format.")
                else:
                    raise ValueError("Invalid credentials file format.")

                creds = Credentials.from_authorized_user_info(info=credentials_json)

                if creds.expired and creds.refresh_token:
                    request = google.auth.transport.requests.Request()
                    creds.refresh(request)
                    with open(TOKEN_FILE, 'w') as second_try_token_file:
                        # noinspection PyTypeChecker
                        json.dump(creds.to_json(), second_try_token_file)
                    print("Credentials refreshed and saved to token.json")
                return creds
            except (ValueError, KeyError, json.JSONDecodeError) as e:
                print(f"Error loading credentials: {e}")
                os.remove(TOKEN_FILE)
                print("Invalid token file deleted. Please re-authenticate.")
                return None
    return None


def find_file(svc, filename: str):
    try:
        page_token = None
        count = 0
        while True:
            results = svc.files().list(pageSize=1000, fields="nextPageToken, files(id, name)",
                                       pageToken=page_token, q="mimeType != 'application/vnd.google-apps.folder' and trashed = false").execute()
            items = results.get('files', [])
            count += len(items)
            print(f'Searching for "{filename}": {count}')
            item = next((i for i in items if i["name"] == filename), None)
            if item:
                return item
            page_token = results.get('nextPageToken')
            if not page_token:
                break

        return None

    except Exception as e:
        print(f"An error occurred: {type(e).__name__}: {e}")
        if hasattr(e, 'details'):
            print(f"Details: {e.details}")
        return None



def get_file_info(svc, root_folder_id):
    # Uses the Drive API to list ALL files and folders with pagination.
    try:
        items = []
        page_token = None
        while True:
            results = svc.files().list(
                pageSize=1000, fields="nextPageToken, files(id, name, mimeType)",
                pageToken=page_token, q=f"'{root_folder_id}' in parents and trashed = false"
            ).execute()
            items += sorted(results.get('files', []), key=lambda itm: itm['name'])
            page_token = results.get('nextPageToken')
            if not page_token:
                break

        if not items:
            print('No files found.')
            return []

        return items

    except Exception as e:
        print(f"An error occurred: {type(e).__name__}: {e}")
        if hasattr(e, 'details'):
            print(f"Details: {e.details}")
        return None


def upload_file(svc, filepath: Path):

    try:
        file_metadata = {'name': filepath.stem + filepath.suffix}
        media = MediaFileUpload(filepath, mimetype='text/csv')
        result = svc.files().create(body=file_metadata, media_body=media, fields='id').execute()
        return result.get("id")
    except Exception as e:
        print(f"An error occurred: {e}")


def add_parent_info(child_item: dict, parent_item: dict = None):
    # child_item['parent_name'] = parent_item['name'] if parent_item else None
    # child_item['parent_id'] = parent_item['id'] if parent_item else None
    child_item['parent_item'] = parent_item


def get_tree(item: dict):
    list = [item['name']]
    while item['parent_item']:
        list.append(item['parent_item']['name'])
        item = item['parent_item']
    list.reverse()
    return ' > '.join(map(str, list))


def folder_lookup(svc, folder_item: dict = None):
    folder_id = folder_item['id'] if folder_item else IMAGE_FOLDER_CODE
    try:
        results_dict = {}
        while True:
            query = f"mimeType='application/vnd.google-apps.folder' and '{folder_id}' in parents and trashed=false"
            results = svc.files().list(q=query, spaces='drive', fields='nextPageToken, files(id, name)').execute()
            items = results.get('files', [])
            if len(items):
                items = sorted(items, key=lambda itm: itm['name'])
                for item in items:
                    add_parent_info(item, folder_item)
                results_dict.update({item['id']: item for item in items})
            page_token = results.get('nextPageToken')
            if not page_token:
                break
        return results_dict
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def file_lookup(svc, folder_item: dict = None):
    folder_id = folder_item['id'] if folder_item else 'root'
    try:
        results_dict = {}
        page_token = None
        while True:
            query = f"mimeType != 'application/vnd.google-apps.folder' and '{folder_id}' in parents and trashed = false"
            fields = "nextPageToken, files(id, name, mimeType)"
            results = svc.files().list(pageSize=1000, fields=fields, pageToken=page_token, q=query).execute()
            items = results.get('files', [])
            items = sorted(items, key=lambda itm: itm['name'])
            if len(items):
                for item in items:
                    add_parent_info(item, folder_item)
                results_dict.update({item['id']: item for item in items})
            page_token = results.get('nextPageToken')
            if not page_token:
                break
        return results_dict
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def delete_file(svc, fid):
    try:
        svc.files().delete(fileId=fid).execute()
        print(f'{fid} has been successfully deleted.')
    except Exception as e:
        print(f"An error occurred: {e}")


def file_name_integrity(loc_code: str, g_dict: dict):
    directions = ['+', '-']
    field_names = ['location', 'direction', 'speed', 'year', 'month', 'day', 'ext']
    try:
        file_fields = {field_names[i]: f for i, f in enumerate(g_dict['name'].split())}
        if (len(file_fields) == len(field_names) and file_fields['location'].upper() == loc_code.upper()
                and file_fields['direction'] in directions and g_dict['mimeType'] == 'image/png'):
            file_date = dt(year=int(file_fields['year']) + 2000, month=int(file_fields['month']), day=int(file_fields['day']))
        else:
            raise ValueError(g_dict['name'])
    except Exception:
        print(f"An error occurred: {g_dict['name']}")
        raise ValueError(g_dict['name'])

    return file_date.date()


if __name__ == '__main__':

    credentials = load_credentials()
    if not credentials:
        credentials = authenticate_user()

    if credentials:
        service = build('drive', 'v3', credentials=credentials)

        if os.getenv("PYCHARM_HOSTED") != '1':
            old_file_name = 'google_urls.csv'
            old_file = find_file(service, old_file_name)
            if old_file:
                delete_file(service, old_file['id'])
            else:
                print(f'"{old_file_name}" not found.')

        location_folder_items = sorted([f for f in get_file_info(service, IMAGE_FOLDER_CODE) if f['mimeType'] == 'application/vnd.google-apps.folder'], key=lambda x: x['name'].upper())
        output_frame = pd.DataFrame()
        for location_folder_item in location_folder_items:
            code = location_folder_item['name'].upper()
            print(f'{code}')
            speed_folder_items = [f for f in get_file_info(service, location_folder_item['id']) if f['mimeType'] == 'application/vnd.google-apps.folder']
            pos_speed_folder_items = sorted([f for f in speed_folder_items if int(f['name']) > 0], key=lambda x: int(x['name']))
            neg_speed_folder_items = sorted([f for f in speed_folder_items if int(f['name']) < 0], key=lambda x: int(x['name']), reverse=True)
            location_frame = pd.DataFrame()

            for items in [pos_speed_folder_items] + [neg_speed_folder_items]:
                for speed_folder_item in items:
                    speed_name = speed_folder_item['name']
                    files = get_file_info(service, speed_folder_item['id'])
                    dates = [file_name_integrity(code, f) for f in files]
                    urls = [FILE_URL_TEMPLATE.substitute(fid=f['id']) for f in files]
                    print(f'        {code} {speed_name} {len(files)}')
                    # speed_frame = pd.DataFrame({'cols': None, 'date': dates, 'speed': int(speed_name), code: urls})
                    speed_frame = pd.DataFrame({'date': dates, code + ' ' + speed_name: urls})
                    speed_frame['date'] = speed_frame['date'].apply(lambda d: d.strftime('%-m/%-d/%Y'))
                    # speed_frame['cols'] = 's-' + speed_frame['speed'].astype('str') + '-' + speed_frame['date'].astype('str')
                    # speed_frame['cols'] = code + speed_frame.speed.astype('str')
                    # speed_frame.drop(['speed'], axis=1, inplace=True)
                    speed_frame.set_index('date', inplace=True)
                    speed_frame = speed_frame.transpose()
                    speed_frame.insert(0, 'code-speed', speed_frame.index)
                    speed_frame['speed'] = int(speed_name)
                    location_frame = pd.concat([location_frame, speed_frame]).reset_index(drop=True)

            expected_values = pd.Series(range(location_frame.speed.min(), location_frame.speed.max() + 1))
            missing_values = expected_values[~expected_values.isin(location_frame.speed)].tolist()
            for value in missing_values:
                location_frame.loc[len(location_frame)] = {'code-speed': 'EMPTY ' + str(value), 'speed': value}

            location_frame.sort_values(by=['speed'], inplace=True)
            location_frame.drop('speed', axis=1, inplace=True)
            # location_frame.set_index('code-speed', inplace=True)
            # location_frame = location_frame.transpose()
            output_frame = pd.concat([output_frame, location_frame])
        output_frame.set_index('code-speed', inplace=True)
        output_frame = output_frame.transpose()
        output_frame.insert(0, 'date', output_frame.index)
        output_frame.reset_index(drop=True, inplace=True)

        print_file_exists(write_df(output_frame, Path(BASE_PATH).joinpath(GOOGLE_NAME)))
        file_id = upload_file(service, Path(BASE_PATH).joinpath(GOOGLE_NAME))
    else:
        print("Authentication failed. Cannot access Google Drive.")
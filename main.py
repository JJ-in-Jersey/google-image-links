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


def get_file_info(svc, root_folder_id):
    # Uses the Drive API to list ALL files and folders with pagination.
    try:
        items = []
        page_token = None
        while True:
            results = svc.files().list(
                pageSize=1000,  # Increase page size for efficiency
                fields="nextPageToken, files(id, name, mimeType)",  # Include mimeType
                pageToken=page_token,
                q=f"'{root_folder_id}' in parents"
            ).execute()
            items += results.get('files', [])
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


def list_folders(svc, parent_id='root', folder_list=None):
    if folder_list is None:
        print('Building folder list')
        folder_list = []
    try:
        query = f"mimeType = 'application/vnd.google-apps.folder' and trashed = false and '{parent_id}' in parents"
        results = svc.files().list(q=query, spaces='drive', fields='nextPageToken, files(id, name)').execute()
        items = results.get('files', [])
        for item in items:
            folder_list.append({'id': item['id'], 'name': item['name'], 'parent': parent_id})
            list_folders(svc, item['id'], folder_list)  # Recursive call
        return folder_list
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def list_files(svc, folder_list):
    print('Building file dictionary')
    file_list = []
    try:
        for folder_id in ['root'] + [f['id'] for f in folder_list]:
            items = []
            page_token = None
            while True:
                results = svc.files().list(
                    pageSize=1000,  # Increase page size for efficiency
                    fields="nextPageToken, files(id, name, mimeType)",  # Include mimeType
                    pageToken=page_token,
                    q=f"'{folder_id}' in parents and trashed = false"
                ).execute()
                items += results.get('files', [])
                page_token = results.get('nextPageToken')
                if not page_token:
                    break
            file_list += items

        name_dict = {f['name']: f for f in file_list}
        return name_dict

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def find_files(f_name: str, f_dict: dict):
    return [f_dict[key] for key in f_dict.keys() if f_name in key]


def delete_file(svc, fid):
    try:
        svc.files().delete(fileId=fid).execute()
        print('fid has been successfully deleted.')
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == '__main__':
    credentials = load_credentials()
    if not credentials:
        credentials = authenticate_user()

    if credentials:
        service = build('drive', 'v3', credentials=credentials)
        f_list = list_folders(service)
        file_dict = list_files(service, f_list)
        values = find_files(GOOGLE_NAME, file_dict)
        if len(values):
            for v in values:
                print(f'{v['name']} found.')
                delete_file(service, v['id'])

        output_frame = pd.DataFrame()
        location_folders = [f for f in get_file_info(service, IMAGE_FOLDER_CODE) if f['mimeType'] == 'application/vnd.google-apps.folder']
        for loc_folder in location_folders:
            code = loc_folder['name'].upper()
            print(f'{code}')
            speed_folders = [f for f in get_file_info(service, loc_folder['id']) if f['mimeType'] == 'application/vnd.google-apps.folder']
            for speed_folder in speed_folders:
                files = get_file_info(service, speed_folder['id'])
                print(f'        {code} {speed_folder['name']} {len(files)}')
                frame = pd.DataFrame(columns=['date', 'id'])
                for file in files:
                    fields = file['name'].split()
                    date = dt(year=int('20' + fields[3]), month=int(fields[4]), day=int(fields[5])).date()
                    frame.loc[len(frame)] = [date, FILE_URL_TEMPLATE.substitute(fid=file['id'])]
                frame.sort_values(by=['date'], inplace=True)
                frame = frame.transpose()
                frame = frame.drop(index=frame.index[0], axis=0).reset_index(drop=True)
                frame.insert(0, 'code', code)
                frame.insert(0, 'speed', int(speed_folder['name']))
                output_frame = pd.concat([output_frame, frame], axis=0)
                del frame
        output_frame.columns = ['speed', 'code'] + [i+1 for i in range(len(output_frame.columns) - 2)]
        output_frame = output_frame.sort_values(by=['code', 'speed']).reset_index(drop=True)
        print_file_exists(write_df(output_frame, Path(BASE_PATH).joinpath(GOOGLE_NAME)))
        file_id = upload_file(service, Path(BASE_PATH).joinpath(GOOGLE_NAME))
    else:
        print("Authentication failed. Cannot access Google Drive.")

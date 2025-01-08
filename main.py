# if item.get('mimeType') == 'application/vnd.google-apps.folder':
import os
import json
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import google.auth.transport.requests
from string import Template
from datetime import datetime as dt
import pandas as pd
from pathlib import Path

from tt_file_tools.file_tools import write_df, print_file_exists

DOWNLOADS = '/users/jason/downloads'
SCOPES = ['https://www.googleapis.com/auth/drive']  # Full Drive access
CLIENT_SECRETS_FILE_NAME = 'client_secret_395566799327-1r0m8lib5rv96vucqogeq7bkkcmls0a2.apps.googleusercontent.com.json'
CLIENT_SECRETS_FILE_PATH = os.path.join(DOWNLOADS, CLIENT_SECRETS_FILE_NAME)
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'
TOKEN_FILE = os.path.join(DOWNLOADS, 'token.json')   # Path to store the token
LOCATION_CODE_DICT = {
    'CCC': '13i6LgPzykPMAx6sBgTVqP5vUNKP5MGRT', 'CDC': '1Qkr3hMgqhOVFgPiPz0c13_BNJsKoEN2l', 'ER': '1rQQN5qz8znQ7g5I_phHj2hMhuhfgXCu7',
    'FIS': '19kntkElXjxBIAu79PsY-g97xU16RmUT0', 'NVS': '1Y_HFIgi1VMTAt3rcfEMbOHzTh9nOuXGo', 'PPC': '1CAYWhapAXKyeDn4K_oFQ-Qmo4JXOQSve',
    'SVS': '1OG2EbO6yUsANuPom7mrEIeiss-p80ai9', 'TR': '1WwISdt8oDjJ5rFMTTea-eHkl7fDidp1A', 'WH': '1nY88WuvZHvKTtSaQukqjjOxLinXgEasK'
}
FILE_URL_TEMPLATE = Template('https://drive.google.com/file/d/$fid/view?usp=drive_link')


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


def get_file_info(creds, root_folder_id):
    # Uses the Drive API to list ALL files and folders with pagination.
    try:
        service = build('drive', 'v3', credentials=creds)
        items = []
        page_token = None

        while True:
            results = service.files().list(
                pageSize=1000,  # Increase page size for efficiency
                fields="nextPageToken, files(id, name, mimeType)",  # Include mimeType
                pageToken=page_token,
                q=f"'{root_folder_id}' in parents"
            ).execute()
            items.extend(results.get('files', []))
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


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    credentials = load_credentials()
    if not credentials:
        credentials = authenticate_user()

    if credentials:
        output_frame = pd.DataFrame()
        for loc_key in LOCATION_CODE_DICT.keys():
            speed_folders = get_file_info(credentials, LOCATION_CODE_DICT[loc_key])
            speed_dict = {speed['name']: speed['id'] for speed in speed_folders}
            for speed_key in speed_dict.keys():
                files = get_file_info(credentials, speed_dict[speed_key])
                frame = pd.DataFrame(columns=['date', 'id'])
                for file in files:
                    fields = file['name'].split()
                    date = dt(year=int('20' + fields[3]), month=int(fields[4]), day=int(fields[5])).date()
                    frame.loc[len(frame)] = [date, FILE_URL_TEMPLATE.substitute(fid=file['id'])]
                frame.sort_values(by=['date'], inplace=True)
                frame = frame.transpose()
                frame = frame.drop(index=frame.index[0], axis=0).reset_index(drop=True)
                frame.insert(0, 'code', loc_key)
                frame.insert(0, 'speed', speed_key)
                output_frame = pd.concat([output_frame, frame], axis=0)
                print(f'{speed_key} {loc_key}')
                del frame
        output_frame.columns = ['speed', 'code'] + [i+1 for i in range(len(output_frame.columns) - 2)]
        output_frame = output_frame.sort_values(by=['code', 'speed']).reset_index(drop=True)
        print_file_exists(write_df(output_frame, Path('/users/jason/fair currents/google_urls.csv')))
    else:
        print("Authentication failed. Cannot access Google Drive.")

// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import {
	authentication,
	AuthenticationProvider,
	AuthenticationProviderAuthenticationSessionsChangeEvent,
	AuthenticationSession,
	Disposable,
	EventEmitter,
	ExtensionContext,
	window,
	ProgressLocation,
	Uri,
	UriHandler,
	commands,
	env
} from 'vscode';
import { v4 as uuid } from 'uuid';
import  fetch  from 'node-fetch';
import { URLSearchParams } from 'url';
import { PromiseAdapter, promiseFromEvent } from './util';

const SESSIONS_SECRET_KEY = "test_key"

type User = {
	pk: number;
	first_name: string;
	last_name: string;
	username: string;
	email: string;
}

type UserData = {
	access_token: string;
	refresh_token: string;
	user: User;
}
// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: ExtensionContext) {
	const subscriptions = context.subscriptions;

	// Use the console to output diagnostic information (console.log) and errors (console.error)
	// This line of code will only be executed once when your extension is activated
	console.log('Congratulations, your extension "vacode-auth" is now active!');

	// The command has been defined in the package.json file
	// Now provide the implementation of the command with registerCommand
	// The commandId parameter must match the command field in package.json
	// context.subscriptions.push(new BeEnAuthenticationProvider(context));
	context.subscriptions.push(commands.registerCommand('vacode-auth.sayHello', async () => {
		const beforeToken = await context.secrets.get(SESSIONS_SECRET_KEY);
		if (beforeToken) {
			console.log('found! token:' + beforeToken)
			const retrieveUserData = await fetch('http://localhost:8000/auth/user/', {
				headers: {
					'Content-Type': 'application/json',
					'Authorization': 'Bearer ' + beforeToken
				},
			})
			retrieveUserData.json().then( async (response) => {
				console.log(response);
			})
		} else {
			const username = await window.showInputBox();
			const password = await window.showInputBox();
			const res = await fetch(`http://localhost:8000/auth/login/`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					'username': username,
					'password': password
				})
			});
			const resJson: Promise<UserData> = res.json();
			console.log(resJson);
			resJson.then( async (data) => {
				await context.secrets.store(SESSIONS_SECRET_KEY, data.access_token);
				const token = await context.secrets.get(SESSIONS_SECRET_KEY);
				console.log(token)
			})
		}
	}))
}

// This method is called when your extension is deactivated
export function deactivate() {}

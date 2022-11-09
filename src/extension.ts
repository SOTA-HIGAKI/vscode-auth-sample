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

// const AUTH_TYPE = `BeEn`;
// const AUTH_NAME = `beEn`;

// export class BeEnAuthenticationProvider implements AuthenticationProvider, Disposable {
// 	private _sessionChangeEmitter = new EventEmitter<AuthenticationProviderAuthenticationSessionsChangeEvent>();
// 	private _disposable: Disposable;
// 	private _pendingStates: string[] = [];
// 	private _codeExchangePromises = new Map<string, { promise: Promise<string>; cancel: EventEmitter<void>}>();
// 	private _uriHandler = new UriEventHandler();

// 	constructor(private readonly context: ExtensionContext) {
// 		this._disposable = Disposable.from(
// 			authentication.registerAuthenticationProvider(
// 				'BeEn',
// 				'BeEn',
// 				this,
// 				{ supportsMultipleAccounts: false }
// 			),
// 			window.registerUriHandler(this._uriHandler)
// 		)
// 	}

// 	get onDidChangeSessions() {
// 		return this._sessionChangeEmitter.event;
// 	}

// 	get redirectUri() {
// 		const publisher = this.context.extension.packageJSON.publisher;
// 		const name = this.context.extension.packageJSON.name;
// 		return `${env.uriScheme}://${publisher}.${name}`;
// 	}

// 	/**
// 	 * @param scopes
// 	 * @returns
// 	 */
// 	public async getSessions(scopes?: string[]): Promise<readonly AuthenticationSession[]> {
// 		const allSessions = await this.context.secrets.get(SESSIONS_SECRET_KEY);

// 		if (allSessions) {
// 			return JSON.parse(allSessions) as AuthenticationSession[];
// 		}
// 		return [];
// 	}

// 	/**
// 	 *
// 	 * @param scopes
// 	 * @returns
// 	 */
// 	public async createSession(scopes: string[]): Promise<AuthenticationSession> {
// 		try {
// 			const token = await this.login(scopes);
// 			if (!token) {
// 				throw new Error('login failed');
// 			}

// 			const userInfo: {
// 				name: string,
// 				email: string,
// 			} = await this.getUserInfo(token);

// 			const session: AuthenticationSession = {
// 				id: uuid(),
// 				accessToken: token,
// 				account: {
// 					label: userInfo.name,
// 					id: userInfo.email,
// 				},
// 				scopes: []
// 			};
// 			await this.context.secrets.store(SESSIONS_SECRET_KEY, JSON.stringify([session]));

// 			this._sessionChangeEmitter.fire({ added: [session], removed: [], changed: [] });

// 			return session;
// 		} catch (err) {
// 			window.showErrorMessage(`Sign in failed: ${err}`);
// 			throw err;
// 		}
// 	}

// 	public async removeSession(sessionId: string): Promise<void> {
// 		const allSessions = await this.context.secrets.get(SESSIONS_SECRET_KEY);
// 		if (allSessions) {
// 			let sessions =JSON.parse(allSessions) as AuthenticationSession[];
// 			const sessionIndex = sessions.findIndex(s => s.id === sessionId);
// 			const session =sessions[sessionIndex];
// 			sessions.splice(sessionIndex, 1);

// 			await this.context.secrets.store(SESSIONS_SECRET_KEY, JSON.stringify(sessions));

// 			if (session) {
// 				this._sessionChangeEmitter.fire({ added: [], removed: [session], changed: [] });
// 			}
// 		}
// 	}

// 	public async dispose() {
// 		this._disposable.dispose();
// 	}

// 	private async login(scopes: string[] = []) {
// 		return await window.withProgress<string>({
// 			location: ProgressLocation.Notification,
// 			title: "signing into BeEngineer...",
// 			cancellable: true,
// 		}, async (_, token) => {
// 			const stateId = uuid();

// 			this._pendingStates.push(stateId);

// 			if (!scopes.includes('openId')) {
// 				scopes.push('openId');
// 			}
// 			if (!scopes.includes('profile')) {
// 				scopes.push('profile');
// 			}
// 			if (!scopes.includes('email')) {
// 			scopes.push('email');
// 			}

// 			const scopeString = scopes.join(' ');

// 			const searchParams = null;
// 			const url = Uri.parse('localhost:8000/auth/login/');
// 			await env.openExternal(url);

// 			let codeExchangePromise = this._codeExchangePromises.get(scopeString);
// 			if (!codeExchangePromise) {
// 				codeExchangePromise = promiseFromEvent(this._uriHandler.event, this.handleUri(scopes));
// 				this._codeExchangePromises.set(scopeString, codeExchangePromise);
// 			}

// 			try {
// 				return await Promise.race([
// 					codeExchangePromise.promise,
// 					new Promise<string>((_, reject) => setTimeout(() => reject('cancelled'), 60000)),
// 					promiseFromEvent<any, any>(token.onCancellationRequested, (_: any, _resolvew: any, reject: (arg0: string) => void) => { reject('User cancelled'); }).promise
// 				]);




// 			} finally {
// 				this._pendingStates = this._pendingStates.filter(state => state !== stateId);
// 				codeExchangePromise?.cancel.fire();
// 				this._codeExchangePromises.delete(scopeString);
// 			}
// 		});
// 	}

// 	private handleUri: (scopes: readonly string[]) => PromiseAdapter<Uri, string> =
// 	(scopes) => async (uri: { fragment: string | URLSearchParams | Record<string, string | readonly string[]> | Iterable<[string, string]> | readonly [string, string][] | undefined; }, resolve: (arg0: string) => void, reject: (arg0: Error) => void) => {
// 		const query = new URLSearchParams(uri.fragment);
// 		const access_token = query.get('access_token');
// 		const state = query.get('state');

// 		if (!access_token) {
// 			reject(new Error('Token not found'));
// 			return;
// 		}
// 		if (!state) {
// 			reject(new Error('Invalid state'));
// 			return;
// 		}

// 		if (!this._pendingStates.some(n => n === state)) {
// 			reject(new Error('state not found'));
// 			return;
// 		}

// 		resolve(access_token);
// 	}

// 	private async getUserInfo(token: string): Promise<any> {
// 		const res = await fetch(`http://localhost:8000/auth/login/`, {
// 			headers: { 'Authorization': 'Bearer ' + token}
// 		});
// 		return await res.json();
// 	}
// }

// // 後で理解する
// class UriEventHandler extends EventEmitter<Uri> implements UriHandler {
// 	public handleUri(uri: Uri) {
// 		this.fire(uri);
// 	}
// }

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
			const username = await window.showInputBox({placeHolder: 'username'});
			const password = await window.showInputBox({placeHolder: 'password'});
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
		const text = getText();
		console.log(text);
	}))
}

export function getText(): string {
	let editor = window.activeTextEditor;
	if (!editor) {
		return "Editor not found!";
	}

	let selection = editor.selection;
	let text = selection.isEmpty ? editor.document.getText() : editor.document.getText(selection);

	return text;
}


// This method is called when your extension is deactivated
export function deactivate() {}

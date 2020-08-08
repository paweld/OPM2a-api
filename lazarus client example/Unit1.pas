unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, ExtCtrls,
  fphttpclient, fpopenssl, openssl, base64;

type

  { TForm1 }

  TForm1 = class(TForm)
    Button1: TButton;
    eurl: TEdit;
    epassword: TEdit;
    elogin: TEdit;
    erate: TEdit;
    epackage: TEdit;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    linfo: TLabel;
    min: TMemo;
    mout: TMemo;
    rgcmd: TRadioGroup;
    procedure Button1Click(Sender: TObject);
    procedure rgcmdClick(Sender: TObject);
  private

  public

  end;

var
  Form1: TForm1;

implementation

{$R *.lfm}

{ TForm1 }

procedure TForm1.Button1Click(Sender: TObject);
var
  Client: TFPHttpClient;
  auth: String;
begin
  if (eurl.Text = '') then
  begin
    ShowMessage('Enter opm package api url!');
    exit;
  end;
  if rgcmd.ItemIndex < 0 then
  begin
    ShowMessage('Choose a command');
    exit;
  end;

  if pos('https://', LowerCase(eurl.Text)) > 0 then
    InitSSLInterface;

  Client := TFPHttpClient.Create(nil);
  //if admin add basic authentication
  if rgcmd.ItemIndex in [0..5] then
  begin
    auth := EncodeStringBase64(elogin.Text + ':' + epassword.Text);
    Client.RequestHeaders.Add('Authorization: Basic ' + auth);
  end;
  try
    Client.AllowRedirect := true;
    case rgcmd.ItemIndex of
      0: mout.Lines.Text := Client.Get(eurl.Text + '/api.php?command=initdb');
      1: mout.Lines.Text := Client.Get(eurl.Text + '/api.php?package=' + epackage.Text);
      2: mout.Lines.Text := Client.Get(eurl.Text + '/api.php?command=ratinghistory&package=' + epackage.Text);
      3: mout.Lines.Text := Client.FormPost(eurl.Text + '/api.php', min.Lines.Text.Replace(#13#10, #10));
      4: mout.Lines.Text := Client.Get(eurl.Text + '/api.php?command=forceupdate&package=' + epackage.Text);
      5: mout.Lines.Text := Client.Get(eurl.Text + '/api.php?command=disable&package=' + epackage.Text);
      6: mout.Lines.Text := Client.Put(eurl.Text + '/api.php?command=setrate&package=' + epackage.Text + '&rate=' + erate.Text);
      7: mout.Lines.Text := Client.Get(eurl.Text + '/api.php?command=rating&package=' + epackage.Text);
    end;
  except
    Client.Free;
  end;
end;

procedure TForm1.rgcmdClick(Sender: TObject);
begin
  linfo.Caption := '';
  case rgcmd.ItemIndex of
    1, 2, 4, 7: linfo.Caption := 'if package name empty then all, otherwise just the package with the chosen name';
    3: linfo.Caption := 'required json input';
    5: linfo.Caption := 'required package name';
    6: linfo.Caption := 'required package name and rate';
  end;
end;

end.


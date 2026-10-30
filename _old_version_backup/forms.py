"""
WTForms for Secure Online Voting System with CSRF and validation.
"""

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import (
    StringField, PasswordField, TextAreaField, DateTimeLocalField,
    RadioField, BooleanField, SubmitField, SelectField, HiddenField
)
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional, ValidationError
from auth_utils import validate_password_strength


class LoginForm(FlaskForm):
    identifier = StringField("Email or Voter ID", validators=[DataRequired(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")


class RegisterForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField("Email Address", validators=[DataRequired(), Email(), Length(max=120)])
    voter_id = StringField("Voter ID / National ID", validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    confirm_password = PasswordField("Confirm Password", validators=[
        DataRequired(),
        EqualTo("password", message="Passwords must match.")
    ])
    submit = SubmitField("Register Voter Account")

    def validate_password(self, field):
        valid, msg = validate_password_strength(field.data)
        if not valid:
            raise ValidationError(msg)


class CreateElectionForm(FlaskForm):
    title = StringField("Election Title", validators=[DataRequired(), Length(min=3, max=200)])
    description = TextAreaField("Description & Guidelines", validators=[Optional(), Length(max=2000)])
    start_time = DateTimeLocalField("Start Time (UTC)", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    end_time = DateTimeLocalField("End Time (UTC)", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    
    key_mode = SelectField("RSA Keypair Configuration", choices=[
        ("generate", "Generate New RSA-2048 Keypair (Encrypted with Passphrase)"),
        ("paste", "Paste Existing RSA Public Key (PEM Format)")
    ], default="generate")
    
    passphrase = PasswordField("Key Passphrase (required for key generation)", validators=[Optional()])
    passphrase_confirm = PasswordField("Confirm Key Passphrase", validators=[
        Optional(),
        EqualTo("passphrase", message="Key passphrases must match.")
    ])
    public_key_pem = TextAreaField("Public Key PEM (SubjectPublicKeyInfo)", validators=[Optional()])
    submit = SubmitField("Create Election")

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators=extra_validators):
            return False
        if self.end_time.data <= self.start_time.data:
            self.end_time.errors.append("End time must be after start time.")
            return False
        if self.key_mode.data == "generate":
            if not self.passphrase.data or len(self.passphrase.data.strip()) < 6:
                self.passphrase.errors.append("A passphrase of at least 6 characters is required for key generation.")
                return False
        elif self.key_mode.data == "paste":
            if not self.public_key_pem.data or "BEGIN PUBLIC KEY" not in self.public_key_pem.data:
                self.public_key_pem.errors.append("A valid RSA Public Key in PEM format is required.")
                return False
        return True


class CandidateForm(FlaskForm):
    name = StringField("Candidate Name", validators=[DataRequired(), Length(min=2, max=100)])
    party = StringField("Political Party / Affiliation", validators=[DataRequired(), Length(max=100)])
    description = TextAreaField("Manifesto / Bio", validators=[Optional(), Length(max=1000)])
    submit = SubmitField("Add Candidate")


class VoteForm(FlaskForm):
    candidate_id = RadioField("Select Candidate", validators=[DataRequired()], coerce=int)
    confirm_accuracy = BooleanField("I confirm my vote selection and understand it is irrevocable.", validators=[DataRequired()])
    submit = SubmitField("Encrypt & Submit Ballot")


class TallyElectionForm(FlaskForm):
    private_key_text = TextAreaField("RSA Private Key (PEM format)", validators=[Optional()])
    private_key_file = FileField("Or Upload Private Key File (.pem)", validators=[Optional()])
    passphrase = PasswordField("Private Key Passphrase", validators=[DataRequired()])
    submit = SubmitField("Verify Hash Chain & Decrypt Tally")


class VerifyReceiptForm(FlaskForm):
    ballot_hash = StringField("Ballot Hash / Tracking Code (SHA-256)", validators=[DataRequired(), Length(min=10, max=64)])
    submit = SubmitField("Verify Ballot in Hash Chain")

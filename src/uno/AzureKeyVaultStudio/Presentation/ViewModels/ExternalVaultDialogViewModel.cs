using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using AzureKeyVaultStudio.Messages;
using AzureKeyVaultStudio.Services;
using CommunityToolkit.Mvvm.Messaging;

namespace AzureKeyVaultStudio.Presentation.ViewModels;

public partial class ExternalVaultDialogViewModel : ObservableValidator
{
    private readonly VaultService? _vaultService;
    public Guid MessengerToken { get; init; } = Guid.NewGuid();

    public ExternalVaultDialogViewModel()
    {
        _vaultService = (Application.Current as App)?.Host?.Services?.GetRequiredService<VaultService>();
    }

    [Required]
    [ObservableProperty]
    public partial string KeyVaultName { get; set; } = "";

    [Required]
    [ObservableProperty]
    public partial string ResourceGroupName { get; set; } = "";

    [Required]
    [MinLength(32)]
    [MaxLength(36)]
    [ObservableProperty]
    public partial string SubscriptionId { get; set; } = "";

    [RelayCommand]
    private void Validate()
    {
        this.ValidateAllProperties();
    }

    [RelayCommand]
    private async Task Submit()
    {
        try
        {
            if (_vaultService == null)
                return;
            var model = await _vaultService.GetKeyVaultResource(subscriptionId: SubscriptionId.Trim(), resourceGroupName: ResourceGroupName.Trim(), vaultName: KeyVaultName.Trim());
            WeakReferenceMessenger.Default.Send(new AddDocumentMessage(model.Data));
            WeakReferenceMessenger.Default.Send(new PinKeyVaultMessage(model));
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == 403)
        {
            // No Azure Resource Manager read on the vault (e.g. a service principal with data-plane access only).
            // Open the vault directly by its data-plane URI; secrets/keys/certs calls go to <name>.vault.azure.net.
            Debug.WriteLine($"ARM read denied, opening vault by URI: {ex.Message}");
            WeakReferenceMessenger.Default.Send(new AddDocumentMessage(
                VaultService.CreateDataPlaneOnlyVaultData(SubscriptionId.Trim(), ResourceGroupName.Trim(), KeyVaultName.Trim())));
        }
        catch (Exception ex)
        {
            WeakReferenceMessenger.Default.Send(new ShowValidationErrorMessage(ex.Message), MessengerToken);
            Debug.WriteLine($"Error fetching Key Vault resource: {ex.Message}");
        }
    }
}

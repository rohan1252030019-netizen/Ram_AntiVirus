namespace Aegis.Core.Interfaces;

public interface INavigationService
{
    object? CurrentView { get; }
    string CurrentViewName { get; }
    event Action? CurrentViewChanged;

    void NavigateTo<TViewModel>() where TViewModel : class;
    void NavigateTo(Type viewModelType);
    void NavigateTo<TViewModel>(Action<TViewModel> parameterInitializer) where TViewModel : class;
    bool CanNavigateBack { get; }
    void NavigateBack();
}
